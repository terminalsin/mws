"""Amazon SQS through boto3."""

import hashlib
import json
import struct
import threading
import time
import uuid

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"


@pytest.fixture
def sqs(endpoint, session_for):
    return session_for().client("sqs", endpoint_url=endpoint)


@pytest.fixture
def queue(sqs):
    return sqs.create_queue(QueueName=f"q-{uuid.uuid4().hex[:8]}")["QueueUrl"]


def code(exc):
    return exc.value.response["Error"]["Code"]


def arn_of(url):
    return f"arn:aws:sqs:us-east-1:{ACCOUNT}:{url.rsplit('/', 1)[1]}"


def md5_of_attributes(attrs):
    """SQS's message attribute digest, computed independently."""
    buf = b""
    for name in sorted(attrs):
        v = attrs[name]
        enc = lambda b: struct.pack(">I", len(b)) + b  # noqa: E731
        buf += enc(name.encode()) + enc(v["DataType"].encode())
        if v["DataType"].startswith("Binary"):
            buf += b"\x02" + enc(v["BinaryValue"])
        else:
            buf += b"\x01" + enc(v["StringValue"].encode())
    return hashlib.md5(buf).hexdigest()


def test_queue_lifecycle(sqs, endpoint):
    name = f"life-{uuid.uuid4().hex[:6]}"
    url = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "40"}, tags={"team": "py"})["QueueUrl"]
    assert url == f"{endpoint}/{ACCOUNT}/{name}"
    assert sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "40"})["QueueUrl"] == url
    with pytest.raises(sqs.exceptions.QueueNameExists) as e:
        sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "41"})
    assert code(e) == "QueueAlreadyExists"
    assert sqs.get_queue_url(QueueName=name)["QueueUrl"] == url
    with pytest.raises(sqs.exceptions.QueueDoesNotExist) as e:
        sqs.get_queue_url(QueueName="missing-" + name)
    assert code(e) == "AWS.SimpleQueueService.NonExistentQueue"

    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    assert attrs["VisibilityTimeout"] == "40"
    assert attrs["QueueArn"] == arn_of(url)
    assert attrs["ApproximateNumberOfMessages"] == "0"
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"DelaySeconds": "2"})
    assert sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["DelaySeconds"])["Attributes"] == {"DelaySeconds": "2"}
    with pytest.raises(sqs.exceptions.InvalidAttributeValue):
        sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "-1"})
    with pytest.raises(sqs.exceptions.InvalidAttributeName):
        sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Nope"])

    sqs.tag_queue(QueueUrl=url, Tags={"env": "dev"})
    sqs.untag_queue(QueueUrl=url, TagKeys=["team"])
    assert sqs.list_queue_tags(QueueUrl=url)["Tags"] == {"env": "dev"}
    assert url in sqs.list_queues(QueueNamePrefix=name)["QueueUrls"]

    sqs.delete_queue(QueueUrl=url)
    with pytest.raises(sqs.exceptions.QueueDoesNotExist):
        sqs.get_queue_attributes(QueueUrl=url)
    with pytest.raises(sqs.exceptions.QueueDeletedRecently):
        sqs.create_queue(QueueName=name)


def test_send_receive_digests_and_visibility(sqs, queue):
    attrs = {
        "s": {"DataType": "String", "StringValue": "héllo"},
        "n": {"DataType": "Number", "StringValue": "42"},
        "b": {"DataType": "Binary", "BinaryValue": b"\x00\xff"},
    }
    sent = sqs.send_message(QueueUrl=queue, MessageBody="body", MessageAttributes=attrs)
    assert sent["MD5OfMessageBody"] == hashlib.md5(b"body").hexdigest()
    assert sent["MD5OfMessageAttributes"] == md5_of_attributes(attrs)

    got = sqs.receive_message(
        QueueUrl=queue, MessageAttributeNames=["All"], MessageSystemAttributeNames=["All"], VisibilityTimeout=30
    )["Messages"][0]
    assert got["MessageId"] == sent["MessageId"]
    assert got["MD5OfMessageAttributes"] == md5_of_attributes(attrs)
    assert got["MessageAttributes"]["b"]["BinaryValue"] == b"\x00\xff"
    assert got["Attributes"]["ApproximateReceiveCount"] == "1"
    assert "Messages" not in sqs.receive_message(QueueUrl=queue)

    sqs.change_message_visibility(QueueUrl=queue, ReceiptHandle=got["ReceiptHandle"], VisibilityTimeout=0)
    again = sqs.receive_message(QueueUrl=queue, MessageSystemAttributeNames=["ApproximateReceiveCount"])["Messages"][0]
    assert again["Attributes"] == {"ApproximateReceiveCount": "2"}
    with pytest.raises(ClientError) as stale:
        sqs.change_message_visibility(QueueUrl=queue, ReceiptHandle=got["ReceiptHandle"], VisibilityTimeout=5)
    assert stale.value.response["Error"]["Code"] == "InvalidParameterValue"
    assert stale.value.response["Error"]["Message"].endswith("Reason: The receipt handle has expired.")
    with pytest.raises(sqs.exceptions.ReceiptHandleIsInvalid):
        sqs.delete_message(QueueUrl=queue, ReceiptHandle="junk")
    sqs.delete_message(QueueUrl=queue, ReceiptHandle=again["ReceiptHandle"])
    assert sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["ApproximateNumberOfMessagesNotVisible"])[
        "Attributes"
    ] == {"ApproximateNumberOfMessagesNotVisible": "0"}

    with pytest.raises(ClientError) as e:
        sqs.receive_message(QueueUrl=queue, WaitTimeSeconds=21)
    assert code(e) == "InvalidParameterValue"


def test_batches(sqs, queue):
    out = sqs.send_message_batch(
        QueueUrl=queue,
        Entries=[{"Id": "a", "MessageBody": "1"}, {"Id": "b", "MessageBody": "2"}, {"Id": "c", "MessageBody": "3", "DelaySeconds": 1000}],
    )
    assert [s["Id"] for s in out["Successful"]] == ["a", "b"]
    assert out["Failed"][0]["Id"] == "c" and out["Failed"][0]["SenderFault"]
    with pytest.raises(sqs.exceptions.BatchEntryIdsNotDistinct):
        sqs.send_message_batch(QueueUrl=queue, Entries=[{"Id": "x", "MessageBody": "1"}, {"Id": "x", "MessageBody": "2"}])
    with pytest.raises(sqs.exceptions.TooManyEntriesInBatchRequest):
        sqs.send_message_batch(QueueUrl=queue, Entries=[{"Id": f"i{i}", "MessageBody": "x"} for i in range(11)])

    msgs = sqs.receive_message(QueueUrl=queue, MaxNumberOfMessages=10)["Messages"]
    assert len(msgs) == 2
    changed = sqs.change_message_visibility_batch(
        QueueUrl=queue, Entries=[{"Id": "v", "ReceiptHandle": msgs[0]["ReceiptHandle"], "VisibilityTimeout": 60}]
    )
    assert changed["Successful"] == [{"Id": "v"}]
    deleted = sqs.delete_message_batch(
        QueueUrl=queue, Entries=[{"Id": str(i), "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)]
    )
    assert len(deleted["Successful"]) == 2


def test_long_poll_wakes_on_send(sqs, queue):
    result = {}

    def poll():
        result["r"] = sqs.receive_message(QueueUrl=queue, WaitTimeSeconds=10)

    t = threading.Thread(target=poll)
    t.start()
    time.sleep(0.3)
    started = time.monotonic()
    sqs.send_message(QueueUrl=queue, MessageBody="wake")
    t.join(timeout=5)
    assert result["r"]["Messages"][0]["Body"] == "wake"
    assert time.monotonic() - started < 2


def test_fifo(sqs):
    url = sqs.create_queue(
        QueueName=f"f-{uuid.uuid4().hex[:6]}.fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
    )["QueueUrl"]
    a = sqs.send_message(QueueUrl=url, MessageBody="one", MessageGroupId="g")
    b = sqs.send_message(QueueUrl=url, MessageBody="one", MessageGroupId="g")
    assert a["MessageId"] == b["MessageId"]
    c = sqs.send_message(QueueUrl=url, MessageBody="two", MessageGroupId="g")
    assert int(c["SequenceNumber"]) > int(a["SequenceNumber"])
    with pytest.raises(ClientError) as e:
        sqs.send_message(QueueUrl=url, MessageBody="x")
    assert code(e) == "MissingParameter"
    first = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1)["Messages"][0]
    assert first["Body"] == "one"
    # The group is blocked while "one" is in flight.
    assert "Messages" not in sqs.receive_message(QueueUrl=url)
    sqs.delete_message(QueueUrl=url, ReceiptHandle=first["ReceiptHandle"])
    assert sqs.receive_message(QueueUrl=url)["Messages"][0]["Body"] == "two"


def test_dead_letter_queue_and_redrive(sqs):
    suffix = uuid.uuid4().hex[:6]
    dlq = sqs.create_queue(QueueName=f"dlq-{suffix}")["QueueUrl"]
    src = sqs.create_queue(
        QueueName=f"src-{suffix}",
        Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": arn_of(dlq), "maxReceiveCount": 2})},
    )["QueueUrl"]
    assert sqs.list_dead_letter_source_queues(QueueUrl=dlq)["queueUrls"] == [src]
    sqs.send_message(QueueUrl=src, MessageBody="bad")
    for _ in range(2):
        assert sqs.receive_message(QueueUrl=src, VisibilityTimeout=0)["Messages"]
    assert "Messages" not in sqs.receive_message(QueueUrl=src)
    dead = sqs.receive_message(QueueUrl=dlq, VisibilityTimeout=0, MessageSystemAttributeNames=["All"])["Messages"][0]
    assert dead["Attributes"]["DeadLetterQueueSourceArn"] == arn_of(src)

    handle = sqs.start_message_move_task(SourceArn=arn_of(dlq))["TaskHandle"]
    tasks = sqs.list_message_move_tasks(SourceArn=arn_of(dlq))["Results"]
    assert tasks[0]["Status"] == "COMPLETED"
    assert tasks[0]["ApproximateNumberOfMessagesMoved"] == 1
    with pytest.raises(sqs.exceptions.UnsupportedOperation):
        sqs.cancel_message_move_task(TaskHandle=handle)
    assert sqs.receive_message(QueueUrl=src)["Messages"][0]["Body"] == "bad"


def test_permissions_purge_and_access(sqs, queue, endpoint, iam, session_for):
    sqs.add_permission(QueueUrl=queue, Label="ops", AWSAccountIds=["111122223333"], Actions=["SendMessage"])
    policy = json.loads(sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["Policy"])["Attributes"]["Policy"])
    assert policy["Statement"][0] == {
        "Sid": "ops",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
        "Action": "SQS:SendMessage",
        "Resource": arn_of(queue),
    }
    sqs.remove_permission(QueueUrl=queue, Label="ops")
    assert "Attributes" not in sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["Policy"])

    sqs.send_message(QueueUrl=queue, MessageBody="x")
    sqs.purge_queue(QueueUrl=queue)
    with pytest.raises(sqs.exceptions.PurgeQueueInProgress):
        sqs.purge_queue(QueueUrl=queue)

    user = f"u-{uuid.uuid4().hex[:6]}"
    iam.create_user(UserName=user)
    key = iam.create_access_key(UserName=user)["AccessKey"]
    other = session_for(key["AccessKeyId"], key["SecretAccessKey"]).client("sqs", endpoint_url=endpoint)
    with pytest.raises(ClientError) as e:
        other.send_message(QueueUrl=queue, MessageBody="x")
    assert code(e) == "AccessDenied"


def query_call(session, endpoint, path="/", **params):
    """An awsQuery request, as SDKs from before SQS's move to JSON send it."""
    import urllib.parse
    import urllib.request

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    body = urllib.parse.urlencode({"Version": "2012-11-05", **params})
    req = AWSRequest(
        method="POST",
        url=endpoint + path,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
    )
    SigV4Auth(session.get_credentials(), "sqs", "us-east-1").add_auth(req)
    http = urllib.request.Request(req.url, data=body.encode(), headers=dict(req.headers), method="POST")
    try:
        with urllib.request.urlopen(http) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_legacy_query_protocol(sqs, endpoint, session_for):
    session = session_for()
    name = f"query-{uuid.uuid4().hex[:6]}"
    status, body = query_call(
        session,
        endpoint,
        Action="CreateQueue",
        QueueName=name,
        **{"Attribute.1.Name": "VisibilityTimeout", "Attribute.1.Value": "20", "Tag.1.Key": "k", "Tag.1.Value": "v"},
    )
    assert status == 200, body
    assert "<CreateQueueResponse" in body and f"<QueueUrl>{endpoint}/{ACCOUNT}/{name}</QueueUrl>" in body
    url = f"{endpoint}/{ACCOUNT}/{name}"
    status, body = query_call(
        session,
        endpoint,
        f"/{ACCOUNT}/{name}",
        Action="SendMessage",
        MessageBody="via query",
        **{
            "MessageAttribute.1.Name": "color",
            "MessageAttribute.1.Value.DataType": "String",
            "MessageAttribute.1.Value.StringValue": "blue",
        },
    )
    assert status == 200, body
    assert f"<MD5OfMessageBody>{hashlib.md5(b'via query').hexdigest()}</MD5OfMessageBody>" in body
    status, body = query_call(
        session, endpoint, Action="GetQueueAttributes", QueueUrl=url, **{"AttributeName.1": "VisibilityTimeout"}
    )
    assert "<Attribute><Name>VisibilityTimeout</Name><Value>20</Value></Attribute>" in body, body
    status, body = query_call(
        session, endpoint, Action="ReceiveMessage", QueueUrl=url, **{"MessageAttributeName.1": "All"}
    )
    assert "<Body>via query</Body>" in body, body
    assert "<Name>color</Name>" in body
    # The JSON API sees the same queue.
    assert sqs.list_queue_tags(QueueUrl=url)["Tags"] == {"k": "v"}

    status, body = query_call(session, endpoint, Action="GetQueueUrl", QueueName="missing-" + name)
    assert status == 400
    assert "<Code>AWS.SimpleQueueService.NonExistentQueue</Code>" in body
    assert "<Type>Sender</Type>" in body

    # Validation and unknown attribute names answer as over awsJson.
    status, body = query_call(
        session, endpoint, Action="GetQueueAttributes", QueueUrl=url, **{"AttributeName.1": "Bogus"}
    )
    assert status == 400 and "<Code>InvalidAttributeName</Code>" in body, body
    assert "<Message>Unknown Attribute Bogus.</Message>" in body
    status, body = query_call(
        session, endpoint, Action="ReceiveMessage", QueueUrl=url, **{"AttributeName.1": "Bogus"}
    )
    assert status == 400 and "<Code>InvalidParameterValue</Code>" in body, body
