import json

from ..dsl import aws_error, aws_ok, scenario


@scenario("sns", "topics and subscriptions", needs=("sqs",))
def _(s):
    s.call("create_topic", Name="${name}", Attributes={"DisplayName": "parity"}, Tags=[{"Key": "team", "Value": "parity"}], save={"topic": "TopicArn"})
    s.call("create_topic", Name="${name}", _note="idempotent: same ARN back")
    s.call("get_topic_attributes", TopicArn="${topic}")
    s.call("set_topic_attributes", TopicArn="${topic}", AttributeName="DisplayName", AttributeValue="renamed")
    s.call("list_tags_for_resource", ResourceArn="${topic}")
    s.call("create_queue", service="sqs", QueueName="${name}-sub", save={"qurl": "QueueUrl"})
    s.call("get_queue_attributes", service="sqs", QueueUrl="${qurl}", AttributeNames=["QueueArn"], save={"qarn": "Attributes.QueueArn"})
    s.call(
        "set_queue_attributes",
        service="sqs",
        QueueUrl="${qurl}",
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": "${qarn}",
                            "Condition": {"ArnEquals": {"aws:SourceArn": "${topic}"}},
                        }
                    ],
                }
            )
        },
        _note="AWS delivers to a queue only if its policy lets SNS send",
    )
    s.call("subscribe", TopicArn="${topic}", Protocol="sqs", Endpoint="${qarn}", Attributes={"RawMessageDelivery": "true"}, ReturnSubscriptionArn=True, save={"sub": "SubscriptionArn"})
    s.call("get_subscription_attributes", SubscriptionArn="${sub}")
    s.call("list_subscriptions_by_topic", TopicArn="${topic}")
    s.call("publish", TopicArn="${topic}", Message="hello parity", Subject="hi", MessageAttributes={"k": {"DataType": "String", "StringValue": "v"}})
    s.call(
        "receive_message",
        service="sqs",
        QueueUrl="${qurl}",
        WaitTimeSeconds=1,
        MessageAttributeNames=["All"],
        _until="Messages",
        _wait=15,
        _note="raw delivery: the body is the message itself",
    )
    s.call("publish_batch", TopicArn="${topic}", PublishBatchRequestEntries=[{"Id": "1", "Message": "a"}, {"Id": "2", "Message": "b"}])
    s.call("publish", TopicArn="${topic}-none", Message="x", expect=aws_error("NotFound", 404, source="SNS API reference"))
    s.call("subscribe", TopicArn="${topic}", Protocol="carrier-pigeon", Endpoint="x", expect=aws_error("InvalidParameter", 400))
    s.call("create_topic", Name="bad name!", expect=aws_error("InvalidParameter", 400))
    s.cleanup("unsubscribe", SubscriptionArn="${sub}")
    s.cleanup("delete_topic", TopicArn="${topic}")
    s.cleanup("delete_queue", service="sqs", QueueUrl="${qurl}")


@scenario("sns", "fifo topic")
def _(s):
    s.call("create_topic", Name="${name}.fifo", Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "true"}, save={"topic": "TopicArn"})
    s.call("publish", TopicArn="${topic}", Message="m", MessageGroupId="g")
    s.call("publish", TopicArn="${topic}", Message="m", expect=aws_error("InvalidParameter", 400))
    s.cleanup("delete_topic", TopicArn="${topic}")


@scenario("events", "buses, rules and targets", needs=("sqs",))
def _(s):
    s.call("create_event_bus", Name="${name}", save={"bus": "EventBusArn"})
    s.call("describe_event_bus", Name="${name}")
    s.call("put_rule", Name="${name}-r", EventBusName="${name}", EventPattern=json.dumps({"source": ["parity.test"]}), State="ENABLED", save={"rule": "RuleArn"})
    s.call("describe_rule", Name="${name}-r", EventBusName="${name}")
    s.call("list_rules", EventBusName="${name}")
    s.call("create_queue", service="sqs", QueueName="${name}-t", save={"qurl": "QueueUrl"})
    s.call("get_queue_attributes", service="sqs", QueueUrl="${qurl}", AttributeNames=["QueueArn"], save={"qarn": "Attributes.QueueArn"})
    s.call(
        "set_queue_attributes",
        service="sqs",
        QueueUrl="${qurl}",
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": "${qarn}",
                            "Condition": {"ArnEquals": {"aws:SourceArn": "${rule}"}},
                        }
                    ],
                }
            )
        },
        _note="AWS delivers to a queue only if its policy lets EventBridge send",
    )
    s.call("put_targets", Rule="${name}-r", EventBusName="${name}", Targets=[{"Id": "q", "Arn": "${qarn}"}])
    s.call("list_targets_by_rule", Rule="${name}-r", EventBusName="${name}")
    s.call("put_events", Entries=[{"Source": "parity.test", "DetailType": "t", "Detail": json.dumps({"k": 1}), "EventBusName": "${name}"}])
    s.call("receive_message", service="sqs", QueueUrl="${qurl}", WaitTimeSeconds=1, _until="Messages", _wait=15)
    s.call(
        "test_event_pattern",
        EventPattern=json.dumps({"source": ["a"], "detail": {"n": [{"numeric": [">", 5]}]}}),
        Event=json.dumps(
            {
                "id": "1", "account": "123456789012", "source": "a", "time": "2024-01-01T00:00:00Z",
                "region": "us-east-1", "resources": [], "detail-type": "t", "detail": {"n": 9},
            }
        ),
        expect=aws_ok({"Result": True}),
    )
    s.call("put_events", Entries=[{"Source": "parity.test", "DetailType": "t", "Detail": "not json", "EventBusName": "${name}"}])
    s.call("disable_rule", Name="${name}-r", EventBusName="${name}")
    s.call("describe_rule", Name="${name}-none", EventBusName="${name}", expect=aws_error("ResourceNotFoundException", 400))
    s.call("put_rule", Name="${name}-bad", EventPattern="{not json", expect=aws_error("InvalidEventPatternException", 400))
    s.cleanup("remove_targets", Rule="${name}-r", EventBusName="${name}", Ids=["q"])
    s.cleanup("delete_rule", Name="${name}-r", EventBusName="${name}")
    s.cleanup("delete_event_bus", Name="${name}")
    s.cleanup("delete_queue", service="sqs", QueueUrl="${qurl}")


@scenario("events", "default bus and archives")
def _(s):
    s.call("describe_event_bus", _shape_only=True)
    s.call("list_event_buses", _shape_only=True)
    s.call("create_archive", ArchiveName="${name}", EventSourceArn="arn:aws:events:${region}:${account}:event-bus/default")
    s.call("describe_archive", ArchiveName="${name}")
    s.cleanup("delete_archive", ArchiveName="${name}")


@scenario("kinesis", "stream lifecycle")
def _(s):
    s.call("create_stream", StreamName="${name}", ShardCount=1)
    s.call("describe_stream", StreamName="${name}", _until="StreamDescription.StreamStatus == 'ACTIVE'", _wait=30, save={"arn": "StreamDescription.StreamARN"})
    s.call("describe_stream_summary", StreamName="${name}")
    s.call("list_shards", StreamName="${name}", save={"shard": "Shards[0].ShardId"})
    s.call("put_record", StreamName="${name}", Data=b"hello", PartitionKey="pk")
    s.call("put_records", StreamName="${name}", Records=[{"Data": b"a", "PartitionKey": "1"}, {"Data": b"b", "PartitionKey": "2"}])
    s.call("get_shard_iterator", StreamName="${name}", ShardId="${shard}", ShardIteratorType="TRIM_HORIZON", save={"it": "ShardIterator"})
    s.call("get_records", ShardIterator="${it}", Limit=10)
    s.call("add_tags_to_stream", StreamName="${name}", Tags={"team": "parity"})
    s.call("list_tags_for_stream", StreamName="${name}")
    s.call("increase_stream_retention_period", StreamName="${name}", RetentionPeriodHours=48)
    s.call("describe_stream", StreamName="${name}-none", expect=aws_error("ResourceNotFoundException", 400))
    s.call("create_stream", StreamName="${name}", ShardCount=1, expect=aws_error("ResourceInUseException", 400))
    s.call("get_shard_iterator", StreamName="${name}", ShardId="shardId-000000000099", ShardIteratorType="LATEST", expect=aws_error("ResourceNotFoundException", 400))
    s.cleanup("delete_stream", StreamName="${name}", EnforceConsumerDeletion=True)


@scenario("firehose", "delivery stream to S3", needs=("s3", "iam"))
def _(s):
    s.call("create_bucket", service="s3", Bucket="${name}")
    s.call(
        "create_role",
        service="iam",
        RoleName="${name}-fh",
        AssumeRolePolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        ),
        save={"role": "Role.Arn"},
    )
    s.call(
        "put_role_policy",
        service="iam",
        RoleName="${name}-fh",
        PolicyName="s3",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}),
    )
    s.call(
        "create_delivery_stream",
        DeliveryStreamName="${name}",
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": "${role}",
            "BucketARN": "arn:aws:s3:::${name}",
            "Prefix": "out/",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
    )
    s.call("describe_delivery_stream", DeliveryStreamName="${name}", _until="DeliveryStreamDescription.DeliveryStreamStatus == 'ACTIVE'", _wait=30)
    s.call("list_delivery_streams", _shape_only=True)
    s.call("put_record", DeliveryStreamName="${name}", Record={"Data": b"row1\n"})
    s.call("put_record_batch", DeliveryStreamName="${name}", Records=[{"Data": b"row2\n"}, {"Data": b"row3\n"}])
    s.call("tag_delivery_stream", DeliveryStreamName="${name}", Tags=[{"Key": "team", "Value": "parity"}])
    s.call("list_tags_for_delivery_stream", DeliveryStreamName="${name}")
    s.call("describe_delivery_stream", DeliveryStreamName="${name}-none", expect=aws_error("ResourceNotFoundException", 400))
    s.cleanup("delete_delivery_stream", DeliveryStreamName="${name}")
    s.cleanup("delete_role_policy", service="iam", RoleName="${name}-fh", PolicyName="s3")
    s.cleanup("delete_role", service="iam", RoleName="${name}-fh")
    s.cleanup("delete_bucket", service="s3", Bucket="${name}", _note="fails if Firehose already flushed objects")
