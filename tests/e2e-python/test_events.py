"""EventBridge through boto3: rules match events and targets receive them."""

import datetime
import http.server
import json
import threading
import time
import uuid

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"
REGION = "us-east-1"


@pytest.fixture
def events(endpoint, session_for):
    return session_for().client("events", endpoint_url=endpoint)


@pytest.fixture
def logs(endpoint, session_for):
    return session_for().client("logs", endpoint_url=endpoint)


def code(exc):
    return exc.value.response["Error"]["Code"]


def uid():
    return uuid.uuid4().hex[:8]


def eventually(fn, timeout=15):
    deadline = time.time() + timeout
    while True:
        value = fn()
        if value:
            return value
        if time.time() > deadline:
            raise AssertionError("timed out waiting")
        time.sleep(0.2)


def log_target(logs, name):
    logs.create_log_group(logGroupName=name)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{name}:*",
            }
        ],
    }
    logs.put_resource_policy(policyName=f"eb-{uid()}", policyDocument=json.dumps(policy))
    return f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{name}"


def logged(logs, group, n=1):
    def read():
        try:
            out = logs.filter_log_events(logGroupName=group)
        except ClientError:
            return None
        msgs = [json.loads(e["message"]) for e in out["events"]]
        return msgs if len(msgs) >= n else None

    return eventually(read)


def test_buses_rules_and_targets(events):
    bus = f"bus-{uid()}"
    arn = events.create_event_bus(Name=bus, Tags=[{"Key": "k", "Value": "v"}])["EventBusArn"]
    assert arn == f"arn:aws:events:{REGION}:{ACCOUNT}:event-bus/{bus}"
    with pytest.raises(ClientError) as e:
        events.create_event_bus(Name=bus)
    assert code(e) == "ResourceAlreadyExistsException"
    assert bus in [b["Name"] for b in events.list_event_buses(NamePrefix=bus)["EventBuses"]]
    events.update_event_bus(Name=bus, Description="d")
    assert events.describe_event_bus(Name=bus)["Description"] == "d"

    rule_arn = events.put_rule(Name="r", EventBusName=bus, EventPattern='{"source":["a"]}', State="DISABLED")["RuleArn"]
    assert rule_arn == f"arn:aws:events:{REGION}:{ACCOUNT}:rule/{bus}/r"
    assert events.describe_rule(Name="r", EventBusName=bus)["State"] == "DISABLED"
    events.enable_rule(Name="r", EventBusName=bus)
    events.disable_rule(Name="r", EventBusName=bus)
    assert [r["Name"] for r in events.list_rules(EventBusName=bus)["Rules"]] == ["r"]
    with pytest.raises(ClientError) as e:
        events.put_rule(Name="x", EventPattern='{"detail":{"n":[{"numeric":["<"]}]}}')
    assert code(e) == "InvalidEventPatternException"

    fn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:f"
    out = events.put_targets(Rule="r", EventBusName=bus, Targets=[{"Id": "1", "Arn": fn, "Input": '{"a":1}'}])
    assert out["FailedEntryCount"] == 0
    assert events.list_targets_by_rule(Rule="r", EventBusName=bus)["Targets"][0]["Input"] == '{"a":1}'
    assert events.list_rule_names_by_target(TargetArn=fn, EventBusName=bus)["RuleNames"] == ["r"]
    with pytest.raises(ClientError) as e:
        events.put_targets(Rule="r", EventBusName=bus, Targets=[{"Id": str(i), "Arn": fn} for i in range(2, 7)])
    assert code(e) == "LimitExceededException"
    events.remove_targets(Rule="r", EventBusName=bus, Ids=["1"])

    events.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "team", "Value": "py"}])
    assert events.list_tags_for_resource(ResourceARN=rule_arn)["Tags"] == [{"Key": "team", "Value": "py"}]
    events.untag_resource(ResourceARN=rule_arn, TagKeys=["team"])
    assert events.list_tags_for_resource(ResourceARN=rule_arn)["Tags"] == []

    events.put_permission(EventBusName=bus, Action="events:PutEvents", Principal="111122223333", StatementId="s1")
    policy = json.loads(events.describe_event_bus(Name=bus)["Policy"])
    assert policy["Statement"][0]["Sid"] == "s1"
    events.remove_permission(EventBusName=bus, StatementId="s1")
    with pytest.raises(ClientError) as e:
        events.remove_permission(EventBusName=bus, StatementId="s1")
    assert code(e) == "ResourceNotFoundException"

    events.delete_rule(Name="r", EventBusName=bus)
    events.delete_event_bus(Name=bus)
    with pytest.raises(ClientError) as e:
        events.describe_event_bus(Name=bus)
    assert code(e) == "ResourceNotFoundException"


def test_event_patterns(events):
    event = json.dumps(
        {
            "id": "1",
            "account": ACCOUNT,
            "source": "app",
            "time": "2026-01-01T00:00:00Z",
            "region": REGION,
            "resources": [],
            "detail-type": "t",
            "detail": {"state": "running", "count": 5, "host": "web-01.example.com"},
        }
    )
    assert events.test_event_pattern(EventPattern='{"detail":{"state":["running"]}}', Event=event)["Result"]
    assert not events.test_event_pattern(EventPattern='{"detail":{"state":[{"anything-but":"running"}]}}', Event=event)["Result"]
    assert events.test_event_pattern(EventPattern='{"detail":{"count":[{"numeric":["=",5]}]}}', Event=event)["Result"]
    assert events.test_event_pattern(EventPattern='{"detail":{"host":[{"wildcard":"web-*.example.com"}]}}', Event=event)["Result"]
    with pytest.raises(ClientError) as e:
        events.test_event_pattern(EventPattern="[]", Event=event)
    assert code(e) == "InvalidEventPatternException"


def test_put_events_reach_log_groups(events, logs):
    group = f"/eb/{uid()}"
    target = log_target(logs, group)
    rule = f"r-{uid()}"
    source = f"py.{uid()}"
    events.put_rule(Name=rule, EventPattern=json.dumps({"source": [source], "detail": {"ok": [True]}}))
    events.put_targets(Rule=rule, Targets=[{"Id": "log", "Arn": target}])
    out = events.put_events(
        Entries=[
            {"Source": source, "DetailType": "Thing", "Detail": json.dumps({"ok": True, "n": 1})},
            {"Source": source, "DetailType": "Thing", "Detail": json.dumps({"ok": False})},
            {"Source": source, "DetailType": "Thing", "Detail": "not json"},
        ]
    )
    assert out["FailedEntryCount"] == 1
    assert out["Entries"][2]["ErrorCode"] == "MalformedDetail"
    [event] = logged(logs, group)
    assert event["id"] == out["Entries"][0]["EventId"]
    assert event["detail"] == {"ok": True, "n": 1}
    assert event["source"] == source


def test_archives_and_replays(events, logs):
    bus = f"arch-{uid()}"
    bus_arn = events.create_event_bus(Name=bus)["EventBusArn"]
    name = f"a-{uid()}"
    archive_arn = events.create_archive(ArchiveName=name, EventSourceArn=bus_arn)["ArchiveArn"]
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)
    events.put_events(Entries=[{"Source": "s", "DetailType": "t", "Detail": "{}", "EventBusName": bus}])
    assert events.describe_archive(ArchiveName=name)["EventCount"] == 1
    events.update_archive(ArchiveName=name, Description="x")
    assert name in [a["ArchiveName"] for a in events.list_archives(NamePrefix=name)["Archives"]]

    group = f"/replay/{uid()}"
    target = log_target(logs, group)
    events.put_rule(Name="replayed", EventBusName=bus, EventPattern='{"replay-name":[{"exists":true}]}')
    events.put_targets(Rule="replayed", EventBusName=bus, Targets=[{"Id": "log", "Arn": target}])
    replay = f"rp-{uid()}"
    events.start_replay(
        ReplayName=replay,
        EventSourceArn=archive_arn,
        EventStartTime=start,
        EventEndTime=start + datetime.timedelta(minutes=5),
        Destination={"Arn": bus_arn},
    )
    eventually(lambda: events.describe_replay(ReplayName=replay)["State"] == "COMPLETED")
    [event] = logged(logs, group)
    assert event["replay-name"] == replay
    assert replay in [r["ReplayName"] for r in events.list_replays(NamePrefix=replay)["Replays"]]
    with pytest.raises(ClientError) as e:
        events.cancel_replay(ReplayName=replay)
    assert code(e) == "IllegalStatusException"
    events.delete_archive(ArchiveName=name)


class Recorder(http.server.BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        Recorder.seen.append((self.path, dict(self.headers), body))
        reply = b'{"access_token":"tok"}' if self.path.startswith("/token") else b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


def test_connections_and_api_destinations(events):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        name = f"c-{uid()}"
        conn = events.create_connection(
            Name=name,
            AuthorizationType="BASIC",
            AuthParameters={"BasicAuthParameters": {"Username": "user", "Password": "pw"}},
        )
        assert conn["ConnectionState"] == "AUTHORIZED"
        assert events.describe_connection(Name=name)["AuthParameters"]["BasicAuthParameters"] == {"Username": "user"}
        assert name in [c["Name"] for c in events.list_connections(NamePrefix=name)["Connections"]]
        events.update_connection(Name=name, Description="basic")
        dest = f"d-{uid()}"
        dest_arn = events.create_api_destination(
            Name=dest, ConnectionArn=conn["ConnectionArn"], InvocationEndpoint=f"{url}/in", HttpMethod="POST"
        )["ApiDestinationArn"]
        assert events.describe_api_destination(Name=dest)["HttpMethod"] == "POST"
        events.update_api_destination(Name=dest, InvocationRateLimitPerSecond=5)
        assert dest in [d["Name"] for d in events.list_api_destinations(NamePrefix=dest)["ApiDestinations"]]
        rule = f"r-{uid()}"
        source = f"py.{uid()}"
        events.put_rule(Name=rule, EventPattern=json.dumps({"source": [source]}))
        events.put_targets(
            Rule=rule,
            Targets=[{"Id": "api", "Arn": dest_arn, "InputTransformer": {"InputPathsMap": {"v": "$.detail.v"}, "InputTemplate": '{"value": <v>}'}}],
        )
        events.put_events(Entries=[{"Source": source, "DetailType": "t", "Detail": '{"v": 9}'}])
        path, headers, body = eventually(lambda: next((s for s in Recorder.seen if s[0] == "/in"), None))
        assert headers["Authorization"] == "Basic dXNlcjpwdw=="
        assert json.loads(body) == {"value": 9}
        assert events.deauthorize_connection(Name=name)["ConnectionState"] == "DEAUTHORIZING"
        events.remove_targets(Rule=rule, Ids=["api"])
        events.delete_rule(Name=rule)
        events.delete_api_destination(Name=dest)
        events.delete_connection(Name=name)
        with pytest.raises(ClientError) as e:
            events.describe_connection(Name=name)
        assert code(e) == "ResourceNotFoundException"
    finally:
        server.shutdown()


def test_endpoints(events, endpoint, session_for):
    west = session_for().client("events", endpoint_url=endpoint, region_name="us-west-2")
    bus = f"g-{uid()}"
    events.create_event_bus(Name=bus)
    west.create_event_bus(Name=bus)
    name = f"ep-{uid()}"
    events.create_endpoint(
        Name=name,
        RoutingConfig={"FailoverConfig": {"Primary": {"HealthCheck": "arn:aws:route53:::healthcheck/x"}, "Secondary": {"Route": "us-west-2"}}},
        ReplicationConfig={"State": "DISABLED"},
        EventBuses=[
            {"EventBusArn": f"arn:aws:events:us-east-1:{ACCOUNT}:event-bus/{bus}"},
            {"EventBusArn": f"arn:aws:events:us-west-2:{ACCOUNT}:event-bus/{bus}"},
        ],
    )
    d = events.describe_endpoint(Name=name)
    assert d["State"] == "ACTIVE"
    events.update_endpoint(Name=name, Description="x")
    assert name in [e["Name"] for e in events.list_endpoints(NamePrefix=name)["Endpoints"]]
    events.delete_endpoint(Name=name)


def test_partner_event_sources(events, logs):
    name = f"aws.partner/py.example/{uid()}/events"
    events.create_partner_event_source(Name=name, Account=ACCOUNT)
    assert events.describe_partner_event_source(Name=name)["Name"] == name
    assert name in [s["Name"] for s in events.list_partner_event_sources(NamePrefix=name)["PartnerEventSources"]]
    accounts = events.list_partner_event_source_accounts(EventSourceName=name)["PartnerEventSourceAccounts"]
    assert accounts[0]["Account"] == ACCOUNT
    assert events.describe_event_source(Name=name)["State"] == "PENDING"
    assert name in [s["Name"] for s in events.list_event_sources(NamePrefix=name)["EventSources"]]
    events.create_event_bus(Name=name, EventSourceName=name)
    events.deactivate_event_source(Name=name)
    events.activate_event_source(Name=name)
    group = f"/partner/{uid()}"
    target = log_target(logs, group)
    events.put_rule(Name="p", EventBusName=name, EventPattern=json.dumps({"source": [name]}))
    events.put_targets(Rule="p", EventBusName=name, Targets=[{"Id": "log", "Arn": target}])
    out = events.put_partner_events(Entries=[{"Source": name, "DetailType": "t", "Detail": '{"x":1}'}])
    assert out["FailedEntryCount"] == 0
    [event] = logged(logs, group)
    assert event["detail"] == {"x": 1}
    events.delete_partner_event_source(Name=name, Account=ACCOUNT)
    assert events.describe_event_source(Name=name)["State"] == "DELETED"
