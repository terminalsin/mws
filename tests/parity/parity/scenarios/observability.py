import time

from ..dsl import aws_error, scenario


def _now_ms():
    return int(time.time() * 1000)


@scenario("logs", "groups, streams and events")
def _(s):
    s.call("create_log_group", logGroupName="/parity/${name}", tags={"team": "parity"})
    s.call("create_log_group", logGroupName="/parity/${name}", expect=aws_error("ResourceAlreadyExistsException", 400))
    s.call("describe_log_groups", logGroupNamePrefix="/parity/${name}")
    s.call("put_retention_policy", logGroupName="/parity/${name}", retentionInDays=7)
    s.call("put_retention_policy", logGroupName="/parity/${name}", retentionInDays=8, expect=aws_error("InvalidParameterException", 400))
    s.call("create_log_stream", logGroupName="/parity/${name}", logStreamName="s1")
    s.call("describe_log_streams", logGroupName="/parity/${name}")
    s.call(
        "put_log_events",
        _params=lambda v: {
            "logGroupName": f"/parity/{v['name']}",
            "logStreamName": "s1",
            "logEvents": [{"timestamp": _now_ms(), "message": "hello parity"}, {"timestamp": _now_ms(), "message": "second line"}],
        },
    )
    s.call("get_log_events", logGroupName="/parity/${name}", logStreamName="s1", startFromHead=True, _until="events", _wait=10)
    s.call("filter_log_events", logGroupName="/parity/${name}", filterPattern="hello", _until="events", _wait=10)
    s.call(
        "put_metric_filter",
        logGroupName="/parity/${name}",
        filterName="f",
        filterPattern="hello",
        metricTransformations=[{"metricName": "Hellos", "metricNamespace": "Parity", "metricValue": "1"}],
    )
    s.call("describe_metric_filters", logGroupName="/parity/${name}")
    s.call("list_tags_for_resource", resourceArn="arn:aws:logs:${region}:${account}:log-group:/parity/${name}")
    s.call("tag_log_group", logGroupName="/parity/${name}", tags={"env": "test"})
    s.call("list_tags_log_group", logGroupName="/parity/${name}")
    s.call("get_log_events", logGroupName="/parity/${name}", logStreamName="nope", expect=aws_error("ResourceNotFoundException", 400))
    s.call("describe_log_streams", logGroupName="/parity/${name}-none", expect=aws_error("ResourceNotFoundException", 400))
    s.cleanup("delete_metric_filter", logGroupName="/parity/${name}", filterName="f")
    s.cleanup("delete_log_stream", logGroupName="/parity/${name}", logStreamName="s1")
    s.cleanup("delete_log_group", logGroupName="/parity/${name}")


@scenario("cloudwatch", "metrics and alarms")
def _(s):
    s.call(
        "put_metric_data",
        Namespace="Parity/${name}",
        MetricData=[{"MetricName": "Latency", "Dimensions": [{"Name": "Api", "Value": "a"}], "Value": 12.5, "Unit": "Milliseconds"}],
    )
    s.call("list_metrics", Namespace="Parity/${name}", _until="Metrics", _wait=10)
    s.call(
        "get_metric_statistics",
        _params=lambda v: {
            "Namespace": f"Parity/{v['name']}",
            "MetricName": "Latency",
            "Dimensions": [{"Name": "Api", "Value": "a"}],
            "StartTime": time.time() - 600,
            "EndTime": time.time() + 60,
            "Period": 60,
            "Statistics": ["Sum", "SampleCount"],
        },
    )
    s.call(
        "put_metric_alarm",
        AlarmName="${name}-alarm",
        Namespace="Parity/${name}",
        MetricName="Latency",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=100,
        ComparisonOperator="GreaterThanThreshold",
    )
    s.call("describe_alarms", AlarmNames=["${name}-alarm"])
    s.call("set_alarm_state", AlarmName="${name}-alarm", StateValue="ALARM", StateReason="parity")
    s.call("describe_alarm_history", AlarmName="${name}-alarm", _shape_only=True)
    s.call("set_alarm_state", AlarmName="${name}-none", StateValue="ALARM", StateReason="x", expect=aws_error("ResourceNotFound", 404))
    s.call("put_dashboard", DashboardName="${name}", DashboardBody='{"widgets": []}')
    s.call("get_dashboard", DashboardName="${name}")
    s.call("get_dashboard", DashboardName="${name}-none", expect=aws_error("ResourceNotFound", 404))
    s.cleanup("delete_dashboards", DashboardNames=["${name}"])
    s.cleanup("delete_alarms", AlarmNames=["${name}-alarm"])
