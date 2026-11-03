"""SNS through boto3: every operation, plus deliveries boto3 users rely on."""

import json
import urllib.parse
import urllib.request
import uuid

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "123456789012"


@pytest.fixture
def sns(endpoint, session_for):
    return session_for().client("sns", endpoint_url=endpoint)


@pytest.fixture
def topic(sns):
    arn = sns.create_topic(Name=f"py-{uuid.uuid4().hex[:8]}")["TopicArn"]
    yield arn
    sns.delete_topic(TopicArn=arn)


def outbox(endpoint, path):
    with urllib.request.urlopen(f"{endpoint}/_aws/sns/{path}") as r:
        return json.loads(r.read())


def error_code(excinfo):
    return excinfo.value.response["Error"]["Code"]


def test_topics_attributes_tags_and_permissions(sns, topic):
    assert topic.startswith(f"arn:aws:sns:us-east-1:{ACCOUNT}:py-")
    assert any(t["TopicArn"] == topic for t in sns.list_topics()["Topics"])
    sns.set_topic_attributes(TopicArn=topic, AttributeName="DisplayName", AttributeValue="Py")
    attrs = sns.get_topic_attributes(TopicArn=topic)["Attributes"]
    assert attrs["DisplayName"] == "Py"
    assert attrs["Owner"] == ACCOUNT

    sns.tag_resource(ResourceArn=topic, Tags=[{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}])
    sns.untag_resource(ResourceArn=topic, TagKeys=["a"])
    assert sns.list_tags_for_resource(ResourceArn=topic)["Tags"] == [{"Key": "b", "Value": "2"}]

    sns.add_permission(TopicArn=topic, Label="p", AWSAccountId=["111122223333"], ActionName=["Publish"])
    assert '"Sid":"p"' in sns.get_topic_attributes(TopicArn=topic)["Attributes"]["Policy"]
    sns.remove_permission(TopicArn=topic, Label="p")
    assert '"Sid":"p"' not in sns.get_topic_attributes(TopicArn=topic)["Attributes"]["Policy"]

    policy = {
        "Name": "p",
        "Version": "2021-06-01",
        "Statement": [
            {
                "DataDirection": "Inbound",
                "Principal": ["*"],
                "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                "Operation": {"Deny": {}},
            }
        ],
    }
    sns.put_data_protection_policy(ResourceArn=topic, DataProtectionPolicy=json.dumps(policy))
    assert json.loads(sns.get_data_protection_policy(ResourceArn=topic)["DataProtectionPolicy"]) == policy

    with pytest.raises(ClientError) as e:
        sns.get_topic_attributes(TopicArn=f"arn:aws:sns:us-east-1:{ACCOUNT}:missing")
    assert error_code(e) == "NotFound"
    assert e.value.response["Error"]["Message"] == "Topic does not exist"


def test_subscriptions_filters_and_email_delivery(endpoint, sns, topic):
    mailbox = f"{uuid.uuid4().hex[:8]}@example.com"
    sub = sns.subscribe(
        TopicArn=topic,
        Protocol="email-json",
        Endpoint=mailbox,
        Attributes={"FilterPolicy": json.dumps({"color": ["red"]})},
        ReturnSubscriptionArn=True,
    )["SubscriptionArn"]
    token = outbox(endpoint, f"subscription-tokens/{sub}")["subscriptionToken"]
    assert sns.confirm_subscription(TopicArn=topic, Token=token)["SubscriptionArn"] == sub
    sns.set_subscription_attributes(SubscriptionArn=sub, AttributeName="FilterPolicyScope", AttributeValue="MessageBody")
    attrs = sns.get_subscription_attributes(SubscriptionArn=sub)["Attributes"]
    assert attrs["FilterPolicyScope"] == "MessageBody"
    assert attrs["PendingConfirmation"] == "false"
    assert any(s["SubscriptionArn"] == sub for s in sns.list_subscriptions()["Subscriptions"])
    assert sns.list_subscriptions_by_topic(TopicArn=topic)["Subscriptions"][0]["Endpoint"] == mailbox

    sns.publish(TopicArn=topic, Message=json.dumps({"color": "red", "n": 1}))
    sns.publish(TopicArn=topic, Message=json.dumps({"color": "blue", "n": 2}))
    out = sns.publish_batch(
        TopicArn=topic,
        PublishBatchRequestEntries=[
            {"Id": "1", "Message": json.dumps({"color": "red", "n": 3})},
            {"Id": "2", "Message": "x", "MessageAttributes": {"bad": {"DataType": "Number", "StringValue": "x"}}},
        ],
    )
    assert [s["Id"] for s in out["Successful"]] == ["1"]
    assert out["Failed"][0]["Code"] == "ParameterValueInvalid"
    mails = outbox(endpoint, f"email-messages?email={urllib.parse.quote(mailbox)}")["emailMessages"]
    bodies = [json.loads(m["body"]) for m in mails[1:]]
    assert [json.loads(b["Message"])["n"] for b in bodies] == [1, 3]
    assert all(b["Type"] == "Notification" and b["SignatureVersion"] == "1" for b in bodies)

    sns.unsubscribe(SubscriptionArn=sub)
    with pytest.raises(ClientError) as e:
        sns.get_subscription_attributes(SubscriptionArn=sub)
    assert error_code(e) == "NotFound"


def test_fifo_topics(sns):
    arn = sns.create_topic(
        Name=f"py-{uuid.uuid4().hex[:8]}.fifo", Attributes={"FifoTopic": "true", "ContentBasedDeduplication": "true"}
    )["TopicArn"]
    a = sns.publish(TopicArn=arn, Message="m", MessageGroupId="g")
    b = sns.publish(TopicArn=arn, Message="m", MessageGroupId="g")
    assert a["MessageId"] == b["MessageId"]
    assert int(sns.publish(TopicArn=arn, Message="n", MessageGroupId="g")["SequenceNumber"]) > int(a["SequenceNumber"])
    with pytest.raises(ClientError) as e:
        sns.publish(TopicArn=arn, Message="m")
    assert error_code(e) == "InvalidParameter"
    sns.delete_topic(TopicArn=arn)


def test_platform_applications(endpoint, sns):
    app = sns.create_platform_application(
        Name=f"py-{uuid.uuid4().hex[:8]}", Platform="APNS", Attributes={"PlatformCredential": "k", "PlatformPrincipal": "c"}
    )["PlatformApplicationArn"]
    sns.set_platform_application_attributes(PlatformApplicationArn=app, Attributes={"SuccessFeedbackSampleRate": "10"})
    assert sns.get_platform_application_attributes(PlatformApplicationArn=app)["Attributes"]["SuccessFeedbackSampleRate"] == "10"
    assert any(a["PlatformApplicationArn"] == app for a in sns.list_platform_applications()["PlatformApplications"])
    ep = sns.create_platform_endpoint(PlatformApplicationArn=app, Token="tok", CustomUserData="u")["EndpointArn"]
    sns.set_endpoint_attributes(EndpointArn=ep, Attributes={"CustomUserData": "v"})
    assert sns.get_endpoint_attributes(EndpointArn=ep)["Attributes"]["CustomUserData"] == "v"
    assert sns.list_endpoints_by_platform_application(PlatformApplicationArn=app)["Endpoints"][0]["EndpointArn"] == ep
    sns.publish(TargetArn=ep, Message=json.dumps({"default": "d", "APNS": '{"aps":{"alert":"hi"}}'}), MessageStructure="json")
    pushed = outbox(endpoint, f"platform-endpoint-messages?endpointArn={urllib.parse.quote(ep)}")["platformEndpointMessages"]
    assert pushed[0]["message"] == '{"aps":{"alert":"hi"}}'
    sns.delete_endpoint(EndpointArn=ep)
    sns.delete_platform_application(PlatformApplicationArn=app)
    with pytest.raises(ClientError) as e:
        sns.get_platform_application_attributes(PlatformApplicationArn=app)
    assert error_code(e) == "NotFound"


def test_sms(endpoint, sns):
    sns.set_sms_attributes(attributes={"DefaultSMSType": "Promotional"})
    assert sns.get_sms_attributes(attributes=["DefaultSMSType"])["attributes"] == {"DefaultSMSType": "Promotional"}
    number = "+1555555" + uuid.uuid4().hex[:4].translate(str.maketrans("abcdef", "123456"))
    sns.publish(PhoneNumber=number, Message="hello")
    msgs = outbox(endpoint, f"sms-messages?phoneNumber={urllib.parse.quote(number)}")["smsMessages"]
    assert msgs[0]["message"] == "hello"
    assert sns.check_if_phone_number_is_opted_out(phoneNumber=number)["isOptedOut"] is False
    req = urllib.request.Request(
        f"{endpoint}/_aws/sns/sms-opt-out?phoneNumber={urllib.parse.quote(number)}", method="POST"
    )
    urllib.request.urlopen(req).read()
    assert sns.check_if_phone_number_is_opted_out(phoneNumber=number)["isOptedOut"] is True
    assert number in sns.list_phone_numbers_opted_out()["phoneNumbers"]
    sns.opt_in_phone_number(phoneNumber=number)
    assert number not in sns.list_phone_numbers_opted_out()["phoneNumbers"]

    assert sns.get_sms_sandbox_account_status()["IsInSandbox"] is False
    sns.create_sms_sandbox_phone_number(PhoneNumber=number, LanguageCode="en-US")
    otp = outbox(endpoint, f"sms-messages?phoneNumber={urllib.parse.quote(number)}")["smsMessages"][-1]["message"].split()[-1]
    sns.verify_sms_sandbox_phone_number(PhoneNumber=number, OneTimePassword=otp)
    listed = sns.list_sms_sandbox_phone_numbers()["PhoneNumbers"]
    assert {"PhoneNumber": number, "Status": "Verified"} in listed
    sns.delete_sms_sandbox_phone_number(PhoneNumber=number)
    assert sns.list_origination_numbers()["PhoneNumbers"] == []


def test_s3_notifications_reach_topics(endpoint, sns, session_for):
    s3 = session_for().client("s3", endpoint_url=endpoint)
    bucket = f"py-{uuid.uuid4().hex[:8]}"
    s3.create_bucket(Bucket=bucket)
    topic = sns.create_topic(Name=f"py-{uuid.uuid4().hex[:8]}")["TopicArn"]
    number = "+1555666" + uuid.uuid4().hex[:4].translate(str.maketrans("abcdef", "123456"))
    sns.subscribe(TopicArn=topic, Protocol="sms", Endpoint=number)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sns:Publish",
                "Resource": topic,
                "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT}},
            }
        ],
    }
    sns.set_topic_attributes(TopicArn=topic, AttributeName="Policy", AttributeValue=json.dumps(policy))
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={"TopicConfigurations": [{"TopicArn": topic, "Events": ["s3:ObjectRemoved:*"]}]},
    )
    s3.put_object(Bucket=bucket, Key="k", Body=b"v")
    s3.delete_object(Bucket=bucket, Key="k")
    msgs = outbox(endpoint, f"sms-messages?phoneNumber={urllib.parse.quote(number)}")["smsMessages"]
    events = [json.loads(m["message"]) for m in msgs]
    assert events[0]["Event"] == "s3:TestEvent"
    assert [e["Records"][0]["eventName"] for e in events[1:]] == ["ObjectRemoved:Delete"]
