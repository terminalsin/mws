"""Amazon CloudWatch through boto3, over each protocol it speaks: Smithy RPC
v2 CBOR (boto3's default), awsJson 1.0 and awsQuery."""

import copy
import datetime as dt
import json
import time
import urllib.request
import uuid

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"


def code(exc):
    return exc.value.response["Error"]["Code"]


def client_for(session, endpoint, protocol=None):
    """A CloudWatch client; `protocol` forces `json` or `query`."""
    if protocol:
        core = session._session
        loader = core.get_component("data_loader")
        original = loader.load_service_model

        def load(service_name, type_name, api_version=None):
            model = original(service_name, type_name, api_version)
            if service_name == "cloudwatch" and type_name == "service-2":
                model = copy.deepcopy(model)
                model["metadata"]["protocol"] = protocol
                model["metadata"]["protocols"] = [protocol]
            return model

        loader.load_service_model = load
    return session.client("cloudwatch", endpoint_url=endpoint)


@pytest.fixture(params=["smithy-rpc-v2-cbor", "json", "query"])
def cw(request, endpoint, session_for):
    protocol = None if request.param == "smithy-rpc-v2-cbor" else request.param
    return client_for(session_for(), endpoint, protocol)


@pytest.fixture
def cbor(endpoint, session_for):
    return client_for(session_for(), endpoint)


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def clock(endpoint, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{endpoint}/_mws/clock", data=data, method="POST" if data else "GET")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def test_metrics_round_trip_on_every_protocol(cw):
    ns = f"Shop-{uuid.uuid4().hex[:6]}"
    t = now().replace(second=0) - dt.timedelta(minutes=5)
    cw.put_metric_data(
        Namespace=ns,
        MetricData=[
            {"MetricName": "Orders", "Dimensions": [{"Name": "Service", "Value": "web"}], "Value": 4.5, "Unit": "Count", "Timestamp": t},
            {"MetricName": "Orders", "Dimensions": [{"Name": "Service", "Value": "web"}], "Values": [1, 2], "Counts": [2, 1], "Timestamp": t},
        ],
    )
    stats = cw.get_metric_statistics(
        Namespace=ns,
        MetricName="Orders",
        Dimensions=[{"Name": "Service", "Value": "web"}],
        StartTime=t - dt.timedelta(minutes=1),
        EndTime=t + dt.timedelta(minutes=1),
        Period=60,
        Statistics=["Sum", "SampleCount", "Maximum"],
    )
    [p] = stats["Datapoints"]
    assert p["Sum"] == 8.5
    assert p["SampleCount"] == 4
    assert p["Maximum"] == 4.5
    p50 = cw.get_metric_statistics(
        Namespace=ns,
        MetricName="Orders",
        Dimensions=[{"Name": "Service", "Value": "web"}],
        StartTime=t,
        EndTime=t + dt.timedelta(minutes=1),
        Period=60,
        ExtendedStatistics=["p50"],
    )["Datapoints"][0]
    assert p50["ExtendedStatistics"]["p50"] == 1.0
    assert p["Timestamp"] == t
    data = cw.get_metric_data(
        StartTime=t,
        EndTime=t + dt.timedelta(minutes=1),
        MetricDataQueries=[
            {"Id": "m", "MetricStat": {"Metric": {"Namespace": ns, "MetricName": "Orders", "Dimensions": [{"Name": "Service", "Value": "web"}]}, "Period": 60, "Stat": "Sum"}, "ReturnData": False},
            {"Id": "double", "Expression": "m * 2", "Label": "Double"},
        ],
    )
    [r] = data["MetricDataResults"]
    assert r["Id"] == "double" and r["Label"] == "Double"
    assert r["Values"] == [17.0]
    assert r["StatusCode"] == "Complete"
    listed = cw.list_metrics(Namespace=ns)["Metrics"]
    assert [m["MetricName"] for m in listed] == ["Orders"]
    with pytest.raises(ClientError) as e:
        cw.put_metric_data(Namespace="AWS/EC2", MetricData=[{"MetricName": "x", "Value": 1}])
    assert code(e) == "InvalidParameterValue"


def test_alarms_on_every_protocol(cw):
    name = f"alarm-{uuid.uuid4().hex[:6]}"
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace="Shop",
        MetricName="Errors",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "team", "Value": "web"}],
    )
    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="manual")
    a = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert a["StateValue"] == "ALARM"
    assert a["AlarmArn"] == f"arn:aws:cloudwatch:us-east-1:{ACCOUNT}:alarm:{name}"
    tags = cw.list_tags_for_resource(ResourceARN=a["AlarmArn"])["Tags"]
    assert tags == [{"Key": "team", "Value": "web"}]
    history = cw.describe_alarm_history(AlarmName=name, HistoryItemType="StateUpdate")["AlarmHistoryItems"]
    assert history and json.loads(history[0]["HistoryData"])["newState"]["stateValue"] == "ALARM"
    cw.delete_alarms(AlarmNames=[name])
    with pytest.raises(ClientError) as e:
        cw.delete_alarms(AlarmNames=[name])
    assert code(e) == "ResourceNotFound"


def test_alarm_actions_reach_sns_and_sqs(cbor, endpoint, session_for):
    s = session_for()
    sqs = s.client("sqs", endpoint_url=endpoint)
    sns = s.client("sns", endpoint_url=endpoint)
    suffix = uuid.uuid4().hex[:6]
    queue = sqs.create_queue(QueueName=f"alarms-{suffix}")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    topic = sns.create_topic(Name=f"alarms-{suffix}")["TopicArn"]
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": queue_arn}]}
    sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": json.dumps(policy)})
    sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn, Attributes={"RawMessageDelivery": "true"})
    name = f"errors-{suffix}"
    cbor.put_metric_alarm(
        AlarmName=name,
        Namespace=f"App-{suffix}",
        MetricName="Errors",
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=10,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        AlarmActions=[topic],
    )
    cbor.put_metric_data(Namespace=f"App-{suffix}", MetricData=[{"MetricName": "Errors", "Value": 12}])
    # Alarms evaluate completed periods, about once a minute: move the
    # emulated clock past the datapoint's minute, and put it back after.
    before = clock(endpoint)["offsetSeconds"]
    clock(endpoint, {"advanceSeconds": 61})
    try:
        for _ in range(100):
            if cbor.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"] == "ALARM":
                break
            time.sleep(0.1)
        else:
            pytest.fail("the alarm never fired")
        # The notification was sent at the advanced time, so read it before
        # the clock goes back (a message isn't visible before it was sent).
        msgs = sqs.receive_message(QueueUrl=queue, WaitTimeSeconds=5)["Messages"]
    finally:
        clock(endpoint, {"offsetSeconds": before})
    body = json.loads(msgs[0]["Body"])
    assert body["AlarmName"] == name
    assert body["NewStateValue"] == "ALARM"
    assert body["Trigger"]["ComparisonOperator"] == "GreaterThanOrEqualToThreshold"


def test_composite_alarms_dashboards_and_mute_rules(cbor):
    suffix = uuid.uuid4().hex[:6]
    child = f"child-{suffix}"
    cbor.put_metric_alarm(AlarmName=child, Namespace="X", MetricName="Y", Statistic="Sum", Period=60, EvaluationPeriods=1, Threshold=1, ComparisonOperator="GreaterThanThreshold")
    parent = f"parent-{suffix}"
    cbor.put_composite_alarm(AlarmName=parent, AlarmRule=f"ALARM({child})")
    cbor.set_alarm_state(AlarmName=child, StateValue="ALARM", StateReason="x")
    for _ in range(100):
        out = cbor.describe_alarms(AlarmNames=[parent], AlarmTypes=["CompositeAlarm"])["CompositeAlarms"]
        if out and out[0]["StateValue"] == "ALARM":
            break
        time.sleep(0.1)
    else:
        pytest.fail("the composite alarm never fired")
    assert cbor.describe_alarms(ParentsOfAlarmName=child, AlarmTypes=["CompositeAlarm"])["CompositeAlarms"][0]["AlarmName"] == parent

    rule = f"mute-{suffix}"
    cbor.put_alarm_mute_rule(Name=rule, Rule={"Schedule": {"Expression": "at(2030-01-01T00:00:00)", "Duration": "PT1H"}}, MuteTargets={"AlarmNames": [child]})
    got = cbor.get_alarm_mute_rule(AlarmMuteRuleName=rule)
    assert got["Status"] == "SCHEDULED" and got["MuteType"] == "ONE_TIME"
    assert any(r["AlarmMuteRuleArn"].endswith(rule) for r in cbor.list_alarm_mute_rules()["AlarmMuteRuleSummaries"])
    cbor.delete_alarm_mute_rule(AlarmMuteRuleName=rule)

    dash = f"dash-{suffix}"
    body = json.dumps({"widgets": [{"type": "text", "x": 0, "y": 0, "width": 6, "height": 3, "properties": {"markdown": "hi"}}]})
    cbor.put_dashboard(DashboardName=dash, DashboardBody=body)
    assert cbor.get_dashboard(DashboardName=dash)["DashboardBody"] == body
    assert dash in [d["DashboardName"] for d in cbor.list_dashboards(DashboardNamePrefix="dash-")["DashboardEntries"]]
    cbor.delete_dashboards(DashboardNames=[dash])
    with pytest.raises(ClientError) as e:
        cbor.get_dashboard(DashboardName=dash)
    assert code(e) == "ResourceNotFound"


def test_logs_metric_filters_publish_and_insights_report(cbor, endpoint, session_for):
    logs = session_for().client("logs", endpoint_url=endpoint)
    group = f"/app/{uuid.uuid4().hex[:6]}"
    ns = f"Logs-{uuid.uuid4().hex[:6]}"
    logs.create_log_group(logGroupName=group)
    logs.create_log_stream(logGroupName=group, logStreamName="s")
    logs.put_metric_filter(
        logGroupName=group,
        filterName="errors",
        filterPattern='{ $.level = "ERROR" }',
        metricTransformations=[{"metricNamespace": ns, "metricName": "Errors", "metricValue": "1", "defaultValue": 0}],
    )
    ts = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group,
        logStreamName="s",
        logEvents=[
            {"timestamp": ts, "message": json.dumps({"level": "ERROR", "user": "ann"})},
            {"timestamp": ts + 1, "message": json.dumps({"level": "INFO", "user": "bob"})},
            {"timestamp": ts + 2, "message": json.dumps({"level": "ERROR", "user": "ann"})},
        ],
    )
    t = now()
    stats = cbor.get_metric_statistics(Namespace=ns, MetricName="Errors", StartTime=t - dt.timedelta(minutes=5), EndTime=t + dt.timedelta(minutes=5), Period=600, Statistics=["Sum", "SampleCount"])
    [p] = stats["Datapoints"]
    # defaultValue only fills periods with no matching events.
    assert p["Sum"] == 2 and p["SampleCount"] == 2

    logs.put_log_events(logGroupName=group, logStreamName="s", logEvents=[{"timestamp": ts + 3, "message": json.dumps({"level": "ERROR", "user": "cat"})}])
    rule = f"users-{uuid.uuid4().hex[:6]}"
    definition = {"Schema": {"Name": "CloudWatchLogRule", "Version": 1}, "LogGroupNames": [group], "LogFormat": "JSON", "Contribution": {"Keys": ["$.user"], "Filters": [{"Match": "$.level", "In": ["ERROR"]}]}, "AggregateOn": "Count"}
    cbor.put_insight_rule(RuleName=rule, RuleDefinition=json.dumps(definition))
    report = cbor.get_insight_rule_report(RuleName=rule, StartTime=t - dt.timedelta(minutes=5), EndTime=t + dt.timedelta(minutes=5), Period=60)
    assert report["AggregationStatistic"] == "Count"
    assert [(c["Keys"], c["ApproximateAggregateValue"]) for c in report["Contributors"]] == [(["ann"], 2.0), (["cat"], 1.0)]
    assert rule in [r["Name"] for r in cbor.describe_insight_rules()["InsightRules"]]
    assert cbor.disable_insight_rules(RuleNames=[rule])["Failures"] == []
    assert cbor.enable_insight_rules(RuleNames=[rule])["Failures"] == []
    assert cbor.delete_insight_rules(RuleNames=[rule, "missing"])["Failures"][0]["FailureResource"] == "missing"


def test_streams_detectors_widgets_and_the_rest(cbor, endpoint, session_for):
    suffix = uuid.uuid4().hex[:6]
    arn = cbor.put_metric_stream(
        Name=f"s-{suffix}",
        FirehoseArn=f"arn:aws:firehose:us-east-1:{ACCOUNT}:deliverystream/d",
        RoleArn=f"arn:aws:iam::{ACCOUNT}:role/r",
        OutputFormat="opentelemetry1.0",
        Tags=[{"Key": "a", "Value": "b"}],
    )["Arn"]
    assert cbor.get_metric_stream(Name=f"s-{suffix}")["State"] == "running"
    cbor.stop_metric_streams(Names=[f"s-{suffix}"])
    assert any(e["Name"] == f"s-{suffix}" and e["State"] == "stopped" for e in cbor.list_metric_streams()["Entries"])
    cbor.start_metric_streams(Names=[f"s-{suffix}"])
    cbor.tag_resource(ResourceARN=arn, Tags=[{"Key": "c", "Value": "d"}])
    cbor.untag_resource(ResourceARN=arn, TagKeys=["a"])
    assert cbor.list_tags_for_resource(ResourceARN=arn)["Tags"] == [{"Key": "c", "Value": "d"}]
    cbor.delete_metric_stream(Name=f"s-{suffix}")

    ns = f"Det-{suffix}"
    detector = {"Namespace": ns, "MetricName": "M", "Dimensions": [], "Stat": "Average"}
    cbor.put_anomaly_detector(SingleMetricAnomalyDetector=detector, Configuration={"MetricTimezone": "Europe/Paris"})
    [d] = cbor.describe_anomaly_detectors(Namespace=ns)["AnomalyDetectors"]
    assert d["Configuration"]["MetricTimezone"] == "Europe/Paris"
    cbor.delete_anomaly_detector(SingleMetricAnomalyDetector=detector)

    cbor.put_managed_insight_rules(ManagedRules=[{"TemplateName": "VpcEndpointService-NewConnectionsByEndpointId-v1", "ResourceARN": f"arn:aws:ec2:us-east-1:{ACCOUNT}:vpc-endpoint-service/vpce-svc-{suffix}"}])
    managed = cbor.list_managed_insight_rules(ResourceARN=f"arn:aws:ec2:us-east-1:{ACCOUNT}:vpc-endpoint-service/vpce-svc-{suffix}")["ManagedRules"]
    assert managed[0]["RuleState"]["State"] == "ENABLED"

    cbor.put_metric_data(Namespace=ns, MetricData=[{"MetricName": "M", "Value": 1}])
    png = cbor.get_metric_widget_image(MetricWidget=json.dumps({"metrics": [[ns, "M"]], "start": "-PT1H"}))["MetricWidgetImage"]
    assert png[:8] == b"\x89PNG\r\n\x1a\n"

    cbor.start_o_tel_enrichment()
    assert cbor.get_o_tel_enrichment()["Status"] == "Running"
    cbor.update_o_tel_enrichment(ExcludeFilters=[{"Namespace": "AWS/S3"}])
    cbor.stop_o_tel_enrichment()

    resource = f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/t-{suffix}"
    cbor.create_resource_metrics_configuration(ResourceArn=resource)
    cbor.update_resource_metrics_configuration(ResourceArn=resource, MetricSelections=[{"IncludeMetrics": ["ThrottledRequests"]}])
    assert cbor.get_resource_metrics_configuration(ResourceArn=resource)["ResourceMetricsConfiguration"]["MetricSelections"] == [{"IncludeMetrics": ["ThrottledRequests"]}]
    cbor.delete_resource_metrics_configuration(ResourceArn=resource)

    kms = session_for().client("kms", endpoint_url=endpoint)
    key = kms.create_key()["KeyMetadata"]["Arn"]
    cbor.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key)
    assert cbor.get_dataset(DatasetIdentifier="default")["KmsKeyArn"] == key
    kms.disable_key(KeyId=key)
    with pytest.raises(ClientError) as e:
        cbor.associate_dataset_kms_key(DatasetIdentifier="default", KmsKeyArn=key)
    assert code(e) == "KmsKeyDisabledException"
    cbor.disassociate_dataset_kms_key(DatasetIdentifier="default")
    assert "KmsKeyArn" not in cbor.get_dataset(DatasetIdentifier="default")

    # Log alarms are listed with their query configuration.
    cbor.put_log_alarm(
        AlarmName=f"log-{suffix}",
        ScheduledQueryConfiguration={
            "QueryString": "fields @message | filter @message like /ERROR/",
            "LogGroupIdentifiers": ["/app"],
            "ScheduledQueryRoleARN": f"arn:aws:iam::{ACCOUNT}:role/q",
            "AggregationExpression": "count(*)",
            "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 300},
        },
        QueryResultsToEvaluate=1,
        QueryResultsToAlarm=1,
        Threshold=0,
        ComparisonOperator="GreaterThanThreshold",
    )
    [la] = cbor.describe_alarms(AlarmNames=[f"log-{suffix}"], AlarmTypes=["LogAlarm"])["LogAlarms"]
    assert la["ScheduledQueryConfiguration"]["ScheduleConfiguration"]["ScheduleExpression"] == "rate(5 minutes)"
    assert cbor.describe_alarm_contributors(AlarmName=f"log-{suffix}")["AlarmContributors"] == []
    assert cbor.describe_alarms_for_metric(Namespace=ns, MetricName="M")["MetricAlarms"] == []
    cbor.disable_alarm_actions(AlarmNames=[f"log-{suffix}"])
    cbor.enable_alarm_actions(AlarmNames=[f"log-{suffix}"])
    cbor.delete_alarms(AlarmNames=[f"log-{suffix}"])


def test_iam_denies_without_permission(cbor, iam, endpoint, session_for):
    user = f"cw-{uuid.uuid4().hex[:6]}"
    iam.create_user(UserName=user)
    iam.put_user_policy(
        UserName=user,
        PolicyName="p",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "cloudwatch:ListMetrics", "Resource": "*"}]}),
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    other = client_for(session_for(key["AccessKeyId"], key["SecretAccessKey"]), endpoint)
    other.list_metrics()
    with pytest.raises(ClientError) as e:
        other.put_metric_data(Namespace="X", MetricData=[{"MetricName": "m", "Value": 1}])
    assert code(e) == "AccessDenied"
