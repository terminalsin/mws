from ..dsl import aws_error, scenario

NONEXISTENT = aws_error(
    "AWS.SimpleQueueService.NonExistentQueue",
    400,
    message="^The specified queue does not exist",
    source="SQS API reference, GetQueueUrl / QueueDoesNotExist",
)


@scenario("sqs", "standard queue lifecycle")
def _(s):
    s.call("create_queue", QueueName="${name}", Attributes={"VisibilityTimeout": "45"}, save={"url": "QueueUrl"})
    s.call("get_queue_url", QueueName="${name}")
    s.call("get_queue_attributes", QueueUrl="${url}", AttributeNames=["All"])
    s.call("set_queue_attributes", QueueUrl="${url}", Attributes={"DelaySeconds": "0", "MaximumMessageSize": "2048"})
    s.call("tag_queue", QueueUrl="${url}", Tags={"team": "parity"})
    s.call("list_queue_tags", QueueUrl="${url}")
    s.call(
        "send_message",
        QueueUrl="${url}",
        MessageBody="hello parity",
        MessageAttributes={"k": {"DataType": "String", "StringValue": "v"}},
    )
    s.call(
        "receive_message",
        QueueUrl="${url}",
        MaxNumberOfMessages=1,
        MessageAttributeNames=["All"],
        WaitTimeSeconds=1,
        _until="Messages",
        _wait=10,
        save={"receipt": "Messages[0].ReceiptHandle"},
    )
    s.call("change_message_visibility", QueueUrl="${url}", ReceiptHandle="${receipt}", VisibilityTimeout=0)
    s.call(
        "send_message_batch",
        QueueUrl="${url}",
        Entries=[{"Id": "a", "MessageBody": "one"}, {"Id": "a", "MessageBody": "two"}],
        expect=aws_error("AWS.SimpleQueueService.BatchEntryIdsNotDistinct", 400, source="SQS API reference, SendMessageBatch"),
    )
    s.call("delete_message", QueueUrl="${url}", ReceiptHandle="garbage", expect=aws_error("ReceiptHandleIsInvalid", 404))
    s.call("purge_queue", QueueUrl="${url}")
    s.call("get_queue_url", QueueName="${name}-missing", expect=NONEXISTENT)
    s.call("create_queue", QueueName="bad name!", expect=aws_error("InvalidParameterValue", 400))
    s.cleanup("delete_queue", QueueUrl="${url}")


@scenario("sqs", "fifo queue")
def _(s):
    s.call(
        "create_queue",
        QueueName="${name}.fifo",
        Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        save={"url": "QueueUrl"},
    )
    s.call("send_message", QueueUrl="${url}", MessageBody="m1", MessageGroupId="g")
    s.call("send_message", QueueUrl="${url}", MessageBody="m2", expect=aws_error("MissingParameter", 400))
    s.call("receive_message", QueueUrl="${url}", AttributeNames=["All"], WaitTimeSeconds=1, _until="Messages", _wait=10)
    s.call("create_queue", QueueName="${name}-nofifo", Attributes={"FifoQueue": "true"}, expect=aws_error("InvalidParameterValue", 400))
    s.cleanup("delete_queue", QueueUrl="${url}")
