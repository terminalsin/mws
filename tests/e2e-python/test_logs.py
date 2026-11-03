"""CloudWatch Logs through boto3."""

import gzip
import json
import threading
import time
import uuid

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"


@pytest.fixture
def logs(endpoint, session_for):
    # StartLiveTail and GetLogObject use a `stream.` host prefix that does
    # not resolve against a local endpoint.
    return session_for().client("logs", endpoint_url=endpoint, config=Config(inject_host_prefix=False))


@pytest.fixture
def group(logs):
    name = f"/test/{uuid.uuid4().hex[:8]}"
    logs.create_log_group(logGroupName=name, tags={"team": "py"})
    logs.create_log_stream(logGroupName=name, logStreamName="s")
    return name


def now_ms():
    return int(time.time() * 1000)


def code(exc):
    return exc.value.response["Error"]["Code"]


def put(logs, group, *messages, stream="s"):
    t = now_ms() - 1000
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": t + i, "message": m} for i, m in enumerate(messages)],
    )
    return t


def test_groups_streams_events_and_filters(logs, group):
    arn = f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:{group}"
    described = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]
    assert described["arn"] == arn + ":*"
    assert described["logGroupArn"] == arn
    with pytest.raises(ClientError) as e:
        logs.create_log_group(logGroupName=group)
    assert code(e) == "ResourceAlreadyExistsException"

    t = put(logs, group, "GET / 200", "GET /x 404", '{"level":"ERROR","ms":300}')
    got = logs.get_log_events(logGroupName=group, logStreamName="s", startFromHead=True)
    assert [e["message"] for e in got["events"]] == ["GET / 200", "GET /x 404", '{"level":"ERROR","ms":300}']
    assert got["events"][0]["timestamp"] == t
    assert len(logs.filter_log_events(logGroupName=group, filterPattern="404")["events"]) == 1
    assert len(logs.filter_log_events(logGroupName=group, filterPattern='{ $.level = "ERROR" }')["events"]) == 1
    assert len(logs.filter_log_events(logGroupName=group, filterPattern="[verb, path, code=4*]")["events"]) == 1
    streams = logs.describe_log_streams(logGroupName=group, orderBy="LastEventTime", descending=True)["logStreams"]
    assert streams[0]["logStreamName"] == "s"
    assert streams[0]["lastEventTimestamp"] == t + 2
    assert any(g["logGroupName"] == group for g in logs.list_log_groups(logGroupNamePattern=group[6:])["logGroups"])
    assert logs.list_aggregate_log_group_summaries(groupBy="DATA_SOURCE_NAME_AND_TYPE")["aggregateLogGroupSummaries"]

    with pytest.raises(ClientError) as e:
        logs.put_log_events(
            logGroupName=group,
            logStreamName="s",
            logEvents=[{"timestamp": t + 5, "message": "b"}, {"timestamp": t, "message": "a"}],
        )
    assert code(e) == "InvalidParameterException"

    logs.put_retention_policy(logGroupName=group, retentionInDays=14)
    assert logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["retentionInDays"] == 14
    logs.delete_retention_policy(logGroupName=group)
    logs.tag_log_group(logGroupName=group, tags={"env": "dev"})
    logs.untag_log_group(logGroupName=group, tags=["team"])
    assert logs.list_tags_log_group(logGroupName=group)["tags"] == {"env": "dev"}
    logs.tag_resource(resourceArn=arn, tags={"cost": "1"})
    logs.untag_resource(resourceArn=arn, tagKeys=["env"])
    assert logs.list_tags_for_resource(resourceArn=arn)["tags"] == {"cost": "1"}
    logs.put_log_group_deletion_protection(logGroupIdentifier=group, deletionProtectionEnabled=True)
    with pytest.raises(ClientError) as e:
        logs.delete_log_group(logGroupName=group)
    assert code(e) == "ValidationException"
    logs.put_log_group_deletion_protection(logGroupIdentifier=group, deletionProtectionEnabled=False)
    logs.put_bearer_token_authentication(logGroupIdentifier=group, bearerTokenAuthenticationEnabled=True)
    logs.delete_log_stream(logGroupName=group, logStreamName="s")
    logs.delete_log_group(logGroupName=group)
    with pytest.raises(ClientError) as e:
        logs.describe_log_streams(logGroupName=group)
    assert code(e) == "ResourceNotFoundException"


def test_insights_queries(logs, group):
    t = put(logs, group, '{"path":"/a","ms":10}', '{"path":"/b","ms":30}', '{"path":"/a","ms":20}')
    qid = logs.start_query(
        logGroupName=group,
        startTime=t // 1000 - 60,
        endTime=t // 1000 + 60,
        queryString="stats count(*) as n, max(ms) as worst by path | sort n desc",
    )["queryId"]
    res = logs.get_query_results(queryId=qid)
    assert res["status"] == "Complete"
    rows = [{f["field"]: f["value"] for f in row} for row in res["results"]]
    assert rows[0] == {"path": "/a", "n": "2", "worst": "20"}
    assert logs.list_log_groups_for_query(queryId=qid)["logGroupIdentifiers"] == [
        f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:{group}"
    ]
    assert any(q["queryId"] == qid for q in logs.describe_queries(logGroupName=group)["queries"])
    with pytest.raises(ClientError) as e:
        logs.stop_query(queryId=qid)
    assert code(e) == "InvalidParameterException"
    with pytest.raises(ClientError) as e:
        logs.start_query(logGroupName=group, startTime=0, endTime=1, queryString="fields | |")
    assert code(e) == "MalformedQueryException"

    ptr_q = logs.start_query(
        logGroupName=group, startTime=t // 1000 - 60, endTime=t // 1000 + 60, queryString="fields @ptr | limit 1"
    )["queryId"]
    ptr = logs.get_query_results(queryId=ptr_q)["results"][0][0]["value"]
    assert "@message" in logs.get_log_record(logRecordPointer=ptr)["logRecord"]
    obj = logs.get_log_object(logObjectPointer=ptr)
    data = b"".join(ev["fields"]["data"] for ev in obj["fieldStream"] if "fields" in ev)
    assert data.startswith(b'{"path":')
    names = [f["name"] for f in logs.get_log_group_fields(logGroupName=group)["logGroupFields"]]
    assert "path" in names
    assert logs.get_log_fields(dataSourceName="aws_vpc", dataSourceType="flow")["logFields"]

    did = logs.put_query_definition(name=f"slow-{group}", queryString="filter ms > 15", logGroupNames=[group])[
        "queryDefinitionId"
    ]
    defs = logs.describe_query_definitions(queryDefinitionNamePrefix=f"slow-{group}")["queryDefinitions"]
    assert defs[0]["queryDefinitionId"] == did
    assert logs.delete_query_definition(queryDefinitionId=did)["success"]


def test_live_tail_streams(logs, group):
    resp = logs.start_live_tail(
        logGroupIdentifiers=[f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:{group}"], logEventFilterPattern="ERROR"
    )
    stream = resp["responseStream"]
    events = iter(stream)
    first = next(events)
    assert "sessionStart" in first

    def writer():
        time.sleep(0.3)
        put(logs, group, "INFO ok", "ERROR bad")

    threading.Thread(target=writer).start()
    deadline = time.time() + 10
    results = []
    for ev in events:
        results.extend(ev.get("sessionUpdate", {}).get("sessionResults", []))
        if results or time.time() > deadline:
            break
    stream.close()
    assert [r["message"] for r in results] == ["ERROR bad"]


def test_policies(logs, group):
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "delivery.logs.amazonaws.com"},
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "*",
                }
            ],
        }
    )
    name = f"p-{uuid.uuid4().hex[:6]}"
    rev = logs.put_resource_policy(policyName=name, policyDocument=doc)["revisionId"]
    with pytest.raises(ClientError) as e:
        logs.put_resource_policy(policyName=name, policyDocument=doc, expectedRevisionId="stale")
    assert code(e) == "OperationAbortedException"
    logs.put_resource_policy(policyName=name, policyDocument=doc, expectedRevisionId=rev)
    assert any(p["policyName"] == name for p in logs.describe_resource_policies()["resourcePolicies"])
    logs.delete_resource_policy(policyName=name)

    dp = json.dumps(
        {
            "Name": "dp",
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "audit",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                },
                {
                    "Sid": "redact",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )
    logs.put_data_protection_policy(logGroupIdentifier=group, policyDocument=dp)
    assert logs.get_data_protection_policy(logGroupIdentifier=group)["policyDocument"] == dp
    time.sleep(0.01)
    put(logs, group, "mail bob@example.com")
    assert logs.get_log_events(logGroupName=group, logStreamName="s")["events"][0]["message"] == "mail ***************"
    clear = logs.get_log_events(logGroupName=group, logStreamName="s", unmask=True)
    assert clear["events"][0]["message"] == "mail bob@example.com"
    logs.delete_data_protection_policy(logGroupIdentifier=group)

    pname = f"idx-{uuid.uuid4().hex[:6]}"
    logs.put_account_policy(
        policyName=pname, policyType="FIELD_INDEX_POLICY", policyDocument='{"Fields":["requestId"]}'
    )
    assert any(
        p["policyName"] == pname for p in logs.describe_account_policies(policyType="FIELD_INDEX_POLICY")["accountPolicies"]
    )
    logs.delete_account_policy(policyName=pname, policyType="FIELD_INDEX_POLICY")
    logs.put_index_policy(logGroupIdentifier=group, policyDocument='{"Fields":["mail"]}')
    assert logs.describe_index_policies(logGroupIdentifiers=[group])["indexPolicies"][0]["source"] == "LOG_GROUP"
    assert logs.describe_field_indexes(logGroupIdentifiers=[group])["fieldIndexes"][0]["fieldIndexName"] == "mail"
    logs.delete_index_policy(logGroupIdentifier=group)


def test_metric_and_subscription_filters(logs, group):
    tested = logs.test_metric_filter(
        filterPattern='{ $.status >= 500 }', logEventMessages=['{"status":503}', '{"status":200}']
    )
    assert [m["eventNumber"] for m in tested["matches"]] == [1]
    logs.put_metric_filter(
        logGroupName=group,
        filterName="5xx",
        filterPattern="{ $.status >= 500 }",
        metricTransformations=[{"metricName": "5xx", "metricNamespace": "Py", "metricValue": "1"}],
    )
    assert logs.describe_metric_filters(logGroupName=group)["metricFilters"][0]["filterName"] == "5xx"
    logs.delete_metric_filter(logGroupName=group, filterName="5xx")

    dname = f"d-{uuid.uuid4().hex[:6]}"
    dest = logs.put_destination(
        destinationName=dname,
        targetArn=f"arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/x",
        roleArn=f"arn:aws:iam::{ACCOUNT}:role/r",
    )["destination"]
    logs.put_destination_policy(
        destinationName=dname,
        accessPolicy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "111122223333"},
                        "Action": "logs:PutSubscriptionFilter",
                        "Resource": dest["arn"],
                    }
                ],
            }
        ),
    )
    assert logs.describe_destinations(DestinationNamePrefix=dname)["destinations"][0]["accessPolicy"]
    logs.put_subscription_filter(logGroupName=group, filterName="all", filterPattern="", destinationArn=dest["arn"])
    assert logs.describe_subscription_filters(logGroupName=group)["subscriptionFilters"][0]["filterName"] == "all"
    logs.delete_subscription_filter(logGroupName=group, filterName="all")
    logs.delete_destination(destinationName=dname)


def test_transformers(logs, group):
    config = [{"parseJSON": {}}, {"lowerCaseString": {"withKeys": ["level"]}}]
    out = logs.test_transformer(transformerConfig=config, logEventMessages=['{"level":"WARN"}'])
    assert json.loads(out["transformedLogs"][0]["transformedEventMessage"]) == {"level": "warn"}
    logs.put_transformer(logGroupIdentifier=group, transformerConfig=config)
    assert len(logs.get_transformer(logGroupIdentifier=group)["transformerConfig"]) == 2
    logs.delete_transformer(logGroupIdentifier=group)


def test_export_to_s3(endpoint, session_for, logs, group):
    s3 = session_for().client("s3", endpoint_url=endpoint)
    bucket = f"export-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=bucket)
    principal = {"Service": "logs.us-east-1.amazonaws.com"}
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": principal, "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket}"},
                    {"Effect": "Allow", "Principal": principal, "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*"},
                ],
            }
        ),
    )
    t = put(logs, group, "exported")
    task = logs.create_export_task(logGroupName=group, fromTime=t - 1000, to=t + 1000, destination=bucket)["taskId"]
    body = s3.get_object(Bucket=bucket, Key=f"exportedlogs/{task}/s/000000.gz")["Body"].read()
    assert gzip.decompress(body).decode().strip().endswith(" exported")
    assert logs.describe_export_tasks(taskId=task)["exportTasks"][0]["status"]["code"] == "COMPLETED"
    with pytest.raises(ClientError) as e:
        logs.cancel_export_task(taskId=task)
    assert code(e) == "InvalidOperationException"
    with pytest.raises(ClientError) as e:
        logs.create_import_task(
            importSourceArn=f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:eventdatastore/abc",
            importRoleArn=f"arn:aws:iam::{ACCOUNT}:role/r",
        )
    assert code(e) == "ResourceNotFoundException"
    assert logs.describe_import_tasks()["imports"] == []
    for call in (logs.describe_import_task_batches, logs.cancel_import_task):
        with pytest.raises(ClientError) as e:
            call(importId="nope")
        assert code(e) == "ResourceNotFoundException"


def test_deliveries(logs, group):
    suffix = uuid.uuid4().hex[:6]
    logs.put_delivery_source(
        name=f"src-{suffix}", resourceArn=f"arn:aws:cloudfront::{ACCOUNT}:distribution/E{suffix}", logType="ACCESS_LOGS"
    )
    dest = logs.put_delivery_destination(
        name=f"dst-{suffix}",
        deliveryDestinationConfiguration={
            "destinationResourceArn": f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:{group}"
        },
    )["deliveryDestination"]
    logs.put_delivery_destination_policy(
        deliveryDestinationName=f"dst-{suffix}",
        deliveryDestinationPolicy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"AWS": "111122223333"}, "Action": "logs:CreateDelivery", "Resource": dest["arn"]}
                ],
            }
        ),
    )
    assert logs.get_delivery_destination_policy(deliveryDestinationName=f"dst-{suffix}")["policy"]
    logs.delete_delivery_destination_policy(deliveryDestinationName=f"dst-{suffix}")
    delivery = logs.create_delivery(deliverySourceName=f"src-{suffix}", deliveryDestinationArn=dest["arn"])["delivery"]
    logs.update_delivery_configuration(id=delivery["id"], recordFields=["timestamp", "status"])
    assert logs.get_delivery(id=delivery["id"])["delivery"]["recordFields"] == ["timestamp", "status"]
    assert any(d["id"] == delivery["id"] for d in logs.describe_deliveries()["deliveries"])
    assert logs.get_delivery_source(name=f"src-{suffix}")["deliverySource"]["service"] == "cloudfront"
    assert logs.get_delivery_destination(name=f"dst-{suffix}")["deliveryDestination"]["deliveryDestinationType"] == "CWL"
    assert logs.describe_delivery_sources()["deliverySources"]
    assert logs.describe_delivery_destinations()["deliveryDestinations"]
    assert logs.describe_configuration_templates(service="cloudfront")["configurationTemplates"]
    logs.delete_delivery(id=delivery["id"])
    logs.delete_delivery_destination(name=f"dst-{suffix}")
    logs.delete_delivery_source(name=f"src-{suffix}")


def test_detectors_tables_scheduled_queries_and_more(logs, group):
    arn = f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:{group}"
    det = logs.create_log_anomaly_detector(logGroupArnList=[arn], evaluationFrequency="TEN_MIN")["anomalyDetectorArn"]
    assert logs.get_log_anomaly_detector(anomalyDetectorArn=det)["evaluationFrequency"] == "TEN_MIN"
    logs.update_log_anomaly_detector(anomalyDetectorArn=det, enabled=True, evaluationFrequency="ONE_HOUR")
    assert any(d["anomalyDetectorArn"] == det for d in logs.list_log_anomaly_detectors()["anomalyDetectors"])
    assert logs.list_anomalies(anomalyDetectorArn=det)["anomalies"] == []
    with pytest.raises(ClientError) as e:
        logs.update_anomaly(anomalyDetectorArn=det, patternId="0" * 32, baseline=True)
    assert code(e) == "ResourceNotFoundException"
    logs.delete_log_anomaly_detector(anomalyDetectorArn=det)

    name = f"t{uuid.uuid4().hex[:6]}"
    table = logs.create_lookup_table(lookupTableName=name, tableBody="k,v\na,1\n")["lookupTableArn"]
    logs.update_lookup_table(lookupTableArn=table, tableBody="k,v\na,1\nb,2\n")
    assert logs.get_lookup_table(lookupTableArn=table)["tableBody"] == "k,v\na,1\nb,2\n"
    assert logs.describe_lookup_tables(lookupTableNamePrefix=name)["lookupTables"][0]["recordsCount"] == 2
    logs.delete_lookup_table(lookupTableArn=table)

    sq = logs.create_scheduled_query(
        name=f"sq-{name}",
        queryLanguage="CWLI",
        queryString="stats count(*)",
        logGroupIdentifiers=[arn],
        scheduleExpression="rate(5 minutes)",
        executionRoleArn=f"arn:aws:iam::{ACCOUNT}:role/sq",
    )["scheduledQueryArn"]
    logs.update_scheduled_query(
        identifier=sq,
        queryLanguage="CWLI",
        queryString="stats count(*) by bin(1h)",
        scheduleExpression="rate(1 hour)",
        executionRoleArn=f"arn:aws:iam::{ACCOUNT}:role/sq",
    )
    assert logs.get_scheduled_query(identifier=sq)["scheduleExpression"] == "rate(1 hour)"
    assert any(q["scheduledQueryArn"] == sq for q in logs.list_scheduled_queries()["scheduledQueries"])
    assert logs.get_scheduled_query_history(identifier=sq, startTime=0, endTime=now_ms())["triggerHistory"] == []
    logs.delete_scheduled_query(identifier=sq)

    integ = f"os{name}"
    logs.put_integration(
        integrationName=integ,
        integrationType="OPENSEARCH",
        resourceConfig={
            "openSearchResourceConfig": {
                "dataSourceRoleArn": f"arn:aws:iam::{ACCOUNT}:role/os",
                "dashboardViewerPrincipals": [f"arn:aws:iam::{ACCOUNT}:root"],
                "retentionDays": 30,
            }
        },
    )
    assert logs.get_integration(integrationName=integ)["integrationStatus"] == "ACTIVE"
    assert any(i["integrationName"] == integ for i in logs.list_integrations()["integrationSummaries"])
    logs.delete_integration(integrationName=integ)

    s3t = f"arn:aws:logs:us-east-1:{ACCOUNT}:integration:{name}"
    sid = logs.associate_source_to_s3_table_integration(
        integrationArn=s3t, dataSource={"name": "cloudtrail", "type": "aws_cloudtrail"}
    )["identifier"]
    assert logs.list_sources_for_s3_table_integration(integrationArn=s3t)["sources"][0]["identifier"] == sid
    logs.disassociate_source_from_s3_table_integration(identifier=sid)

    logs.put_storage_tier_policy(storageTier="STANDARD")
    assert logs.get_storage_tier_policy()["storageTier"] == "STANDARD"
    logs.put_syslog_configuration(logGroupIdentifier=group, vpcEndpointId="vpce-0abc0abc0abc0abc0")
    assert logs.list_syslog_configurations(logGroupIdentifier=group)["syslogConfigurations"]
    logs.delete_syslog_configuration(logGroupIdentifier=group, vpcEndpointId="vpce-0abc0abc0abc0abc0")


def test_kms_association(endpoint, session_for, logs, group):
    kms = session_for().client("kms", endpoint_url=endpoint)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "Action": "kms:*", "Resource": "*"},
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.us-east-1.amazonaws.com"},
                "Action": ["kms:Encrypt*", "kms:Decrypt*", "kms:GenerateDataKey*"],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(Policy=json.dumps(policy))["KeyMetadata"]["Arn"]
    logs.associate_kms_key(logGroupName=group, kmsKeyId=key)
    assert logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["kmsKeyId"] == key
    logs.disassociate_kms_key(logGroupName=group)
    plain = kms.create_key()["KeyMetadata"]["Arn"]
    with pytest.raises(ClientError) as e:
        logs.associate_kms_key(logGroupName=group, kmsKeyId=plain)
    assert code(e) == "AccessDeniedException"
