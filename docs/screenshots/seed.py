"""Seed a running MWS with a small, realistic "storefront" account for the
README screenshots (docs/screenshots/capture.cjs).

    MWS_ASYNC_DELAY_MS=0 cargo run -p mws &
    pip install boto3
    python docs/screenshots/seed.py          # MWS on http://localhost:4566
"""

import io
import json
import os
import time
import zipfile

import boto3

ENDPOINT = os.environ.get("MWS_ENDPOINT", "http://localhost:4566")
ACCOUNT = "123456789012"
REGION = "us-east-1"
SESSION = boto3.session.Session(
    aws_access_key_id="AKIAMWSROOTEXAMPLE00",
    aws_secret_access_key="mwsRootSecretAccessKeyEXAMPLEKEY00000000",
    region_name=REGION,
)


def client(name):
    return SESSION.client(name, endpoint_url=ENDPOINT)


def step(label, fn):
    try:
        return fn()
    except Exception as err:  # keep seeding; a missing extra is fine for screenshots
        print(f"  skipped {label}: {err}")
        return None


iam, kms, s3, sqs, sns = client("iam"), client("kms"), client("s3"), client("sqs"), client("sns")
lam, logs, cw, events = client("lambda"), client("logs"), client("cloudwatch"), client("events")
ec2, r53, pca, sm, ssm = client("ec2"), client("route53"), client("acm-pca"), client("secretsmanager"), client("ssm")
kinesis, cfn, orgs = client("kinesis"), client("cloudformation"), client("organizations")

trust = lambda svc: json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": svc}, "Action": "sts:AssumeRole"}]})

# IAM
print("IAM")
for user, team in [("alice", "platform"), ("bob", "payments"), ("ci-deployer", "platform")]:
    step(user, lambda: iam.create_user(UserName=user, Tags=[{"Key": "team", "Value": team}]))
step("group", lambda: iam.create_group(GroupName="developers"))
for user in ["alice", "bob"]:
    step("membership", lambda: iam.add_user_to_group(GroupName="developers", UserName=user))
step("policy", lambda: iam.create_policy(PolicyName="OrdersReadWrite", PolicyDocument=json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "Queue", "Effect": "Allow", "Action": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
         "Resource": f"arn:aws:sqs:{REGION}:{ACCOUNT}:orders"},
        {"Sid": "Receipts", "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
         "Resource": "arn:aws:s3:::storefront-receipts/*"},
        {"Sid": "TaggedKeys", "Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*",
         "Condition": {"StringEquals": {"aws:ResourceTag/app": "storefront"}}},
    ]})))
for role, svc in [("orders-processor", "lambda.amazonaws.com"), ("checkout-api", "lambda.amazonaws.com"),
                  ("web-server", "ec2.amazonaws.com"), ("ecs-task-execution", "ecs-tasks.amazonaws.com")]:
    step(role, lambda: iam.create_role(RoleName=role, AssumeRolePolicyDocument=trust(svc),
                                       Tags=[{"Key": "app", "Value": "storefront"}]))
for role in ["orders-processor", "checkout-api"]:
    step("attach", lambda: iam.attach_role_policy(RoleName=role, PolicyArn=f"arn:aws:iam::{ACCOUNT}:policy/OrdersReadWrite"))
step("attach ro", lambda: iam.attach_role_policy(RoleName="web-server", PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess"))
role_arn = lambda name: f"arn:aws:iam::{ACCOUNT}:role/{name}"

# KMS
print("KMS")
key = step("key", lambda: kms.create_key(Description="Storefront data key",
                                        Tags=[{"TagKey": "app", "TagValue": "storefront"}]))
key_id = key["KeyMetadata"]["KeyId"] if key else None
if key_id:
    step("alias", lambda: kms.create_alias(AliasName="alias/storefront", TargetKeyId=key_id))
    step("rotation", lambda: kms.enable_key_rotation(KeyId=key_id))
signing = step("sign key", lambda: kms.create_key(Description="Webhook signing", KeyUsage="SIGN_VERIFY",
                                                 KeySpec="ECC_NIST_P256"))
if signing:
    step("alias2", lambda: kms.create_alias(AliasName="alias/webhook-signing", TargetKeyId=signing["KeyMetadata"]["KeyId"]))

# S3
print("S3")
for bucket in ["storefront-assets", "storefront-receipts", "storefront-logs"]:
    step(bucket, lambda: s3.create_bucket(Bucket=bucket))
step("versioning", lambda: s3.put_bucket_versioning(Bucket="storefront-assets", VersioningConfiguration={"Status": "Enabled"}))
if key_id:
    step("sse", lambda: s3.put_bucket_encryption(Bucket="storefront-receipts", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key_id}}]}))
for path, body, ctype in [
    ("index.html", b"<!doctype html><h1>Storefront</h1>", "text/html"),
    ("css/site.css", b"body{font-family:system-ui}", "text/css"),
    ("js/app.js", b"console.log('storefront');", "application/javascript"),
    ("img/logo.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>", "image/svg+xml"),
    ("products/catalog.json", json.dumps([{"sku": f"SKU-{i:04}", "price": 9 + i} for i in range(40)]).encode(), "application/json"),
]:
    step(path, lambda: s3.put_object(Bucket="storefront-assets", Key=path, Body=body, ContentType=ctype))
for i in range(6):
    step("receipt", lambda: s3.put_object(Bucket="storefront-receipts", Key=f"2026/11/order-{1040 + i}.json",
                                          Body=json.dumps({"order": 1040 + i, "total": 42.5 + i}).encode()))
step("lifecycle", lambda: s3.put_bucket_lifecycle_configuration(Bucket="storefront-logs", LifecycleConfiguration={
    "Rules": [{"ID": "expire-30d", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 30}}]}))

# SQS + SNS
print("SQS, SNS")
dlq = step("dlq", lambda: sqs.create_queue(QueueName="orders-dlq"))
dlq_arn = f"arn:aws:sqs:{REGION}:{ACCOUNT}:orders-dlq"
q = step("orders", lambda: sqs.create_queue(QueueName="orders", Attributes={
    "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "5"}), "VisibilityTimeout": "60"}))
step("fifo", lambda: sqs.create_queue(QueueName="payments.fifo", Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"}))
step("emails", lambda: sqs.create_queue(QueueName="email-notifications"))
if q:
    for i in range(12):
        step("msg", lambda: sqs.send_message(QueueUrl=q["QueueUrl"], MessageBody=json.dumps({"orderId": 1040 + i, "items": i % 4 + 1})))
topic = step("topic", lambda: sns.create_topic(Name="order-events"))
alerts = step("alerts", lambda: sns.create_topic(Name="ops-alerts"))
if topic:
    email_q = f"arn:aws:sqs:{REGION}:{ACCOUNT}:email-notifications"
    step("qpolicy", lambda: sqs.set_queue_attributes(QueueUrl=f"{ENDPOINT}/{ACCOUNT}/email-notifications", Attributes={"Policy": json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                                                "Action": "sqs:SendMessage", "Resource": email_q}]})}))
    step("sub", lambda: sns.subscribe(TopicArn=topic["TopicArn"], Protocol="sqs", Endpoint=email_q))
if alerts:
    step("email sub", lambda: sns.subscribe(TopicArn=alerts["TopicArn"], Protocol="email", Endpoint="oncall@example.com"))

# Lambda
print("Lambda")
code = """import json, os, random

def handler(event, context):
    order = event.get("orderId", random.randint(1000, 9999))
    print(json.dumps({"level": "INFO", "msg": "processing order", "orderId": order}))
    total = round(sum(i["price"] * i["qty"] for i in event.get("items", [])), 2)
    return {"orderId": order, "status": "CONFIRMED", "total": total}
"""
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    zf.writestr("app.py", code)
for name, role, desc in [("process-order", "orders-processor", "Confirms orders from the orders queue"),
                         ("checkout", "checkout-api", "Checkout API behind the function URL"),
                         ("send-receipt", "orders-processor", "Emails a receipt for each order")]:
    step(name, lambda: lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn(role), Handler="app.handler",
                                          Code={"ZipFile": buf.getvalue()}, Description=desc, MemorySize=256, Timeout=15,
                                          Environment={"Variables": {"TABLE": "orders", "STAGE": "prod"}},
                                          Tags={"app": "storefront"}))
time.sleep(1.5)
if q:
    step("esm", lambda: lam.create_event_source_mapping(FunctionName="process-order", EventSourceArn=f"arn:aws:sqs:{REGION}:{ACCOUNT}:orders",
                                                       BatchSize=10, Enabled=False))
step("url", lambda: lam.create_function_url_config(FunctionName="checkout", AuthType="NONE"))
for i in range(8):
    step("invoke", lambda: lam.invoke(FunctionName="process-order", Payload=json.dumps(
        {"orderId": 2000 + i, "items": [{"price": 19.99, "qty": i % 3 + 1}, {"price": 4.5, "qty": 2}]}).encode()))
for i in range(4):
    step("invoke2", lambda: lam.invoke(FunctionName="checkout", Payload=b'{"items":[{"price":12,"qty":1}]}'))

# CloudWatch metrics, alarms, logs
print("CloudWatch")
now = time.time()
for i in range(60):
    ts = now - (60 - i) * 60
    step("metric", lambda: cw.put_metric_data(Namespace="Storefront", MetricData=[
        {"MetricName": "Orders", "Dimensions": [{"Name": "Stage", "Value": "prod"}], "Timestamp": ts,
         "Value": 40 + 25 * ((i % 20) / 20) + (i % 7) * 3, "Unit": "Count"},
        {"MetricName": "CheckoutLatency", "Dimensions": [{"Name": "Stage", "Value": "prod"}], "Timestamp": ts,
         "Value": 120 + (i % 11) * 9 + (180 if i > 52 else 0), "Unit": "Milliseconds"}]))
alarm_actions = [alerts["TopicArn"]] if alerts else []
step("alarm", lambda: cw.put_metric_alarm(AlarmName="checkout-latency-high", Namespace="Storefront", MetricName="CheckoutLatency",
                                         Dimensions=[{"Name": "Stage", "Value": "prod"}], Statistic="Average", Period=60,
                                         EvaluationPeriods=1, Threshold=250, ComparisonOperator="GreaterThanThreshold",
                                         AlarmActions=alarm_actions, AlarmDescription="p50 checkout latency over 250 ms"))
step("alarm2", lambda: cw.put_metric_alarm(AlarmName="orders-dlq-not-empty", Namespace="AWS/SQS", MetricName="ApproximateNumberOfMessagesVisible",
                                          Dimensions=[{"Name": "QueueName", "Value": "orders-dlq"}], Statistic="Maximum", Period=60,
                                          EvaluationPeriods=1, Threshold=0, ComparisonOperator="GreaterThanThreshold",
                                          AlarmActions=alarm_actions))
step("alarm-state", lambda: cw.set_alarm_state(AlarmName="checkout-latency-high", StateValue="ALARM",
                                               StateReason="Threshold Crossed: 1 datapoint [311.0] was greater than the threshold (250.0)."))
step("log group", lambda: logs.create_log_group(logGroupName="/storefront/web"))
step("retention", lambda: logs.put_retention_policy(logGroupName="/storefront/web", retentionInDays=14))
step("stream", lambda: logs.create_log_stream(logGroupName="/storefront/web", logStreamName="web-1"))
msgs = [{"timestamp": int((now - 300 + i * 5) * 1000), "message": json.dumps({
    "level": ["INFO", "INFO", "WARN", "INFO", "ERROR"][i % 5], "path": ["/", "/cart", "/checkout", "/products", "/api/pay"][i % 5],
    "status": [200, 200, 302, 200, 502][i % 5], "ms": 12 + (i * 7) % 90})} for i in range(50)]
step("events", lambda: logs.put_log_events(logGroupName="/storefront/web", logStreamName="web-1", logEvents=msgs))

# EventBridge
print("EventBridge")
step("bus", lambda: events.create_event_bus(Name="storefront"))
step("rule", lambda: events.put_rule(Name="order-placed", EventBusName="storefront", EventPattern=json.dumps({
    "source": ["storefront.orders"], "detail-type": ["OrderPlaced"], "detail": {"total": [{"numeric": [">", 100]}]}})))
step("target", lambda: events.put_targets(Rule="order-placed", EventBusName="storefront", Targets=[
    {"Id": "receipt", "Arn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:send-receipt"}]))
step("schedule", lambda: events.put_rule(Name="nightly-report", ScheduleExpression="cron(0 3 * * ? *)"))

# Secrets, parameters
print("Secrets Manager, SSM")
step("secret", lambda: sm.create_secret(Name="storefront/db", KmsKeyId=key_id or "alias/aws/secretsmanager",
                                       SecretString=json.dumps({"username": "app", "password": "s3cr3t-Pa55"}),
                                       Description="Database credentials"))
step("secret2", lambda: sm.create_secret(Name="storefront/stripe", SecretString="sk_test_example"))
for name, value, typ in [("/storefront/prod/feature-flags", '{"newCheckout":true}', "String"),
                         ("/storefront/prod/api-url", "https://api.storefront.example", "String"),
                         ("/storefront/prod/db-password", "s3cr3t-Pa55", "SecureString")]:
    step(name, lambda: ssm.put_parameter(Name=name, Value=value, Type=typ, Overwrite=True))

# VPC + EC2
print("EC2, VPC")
vpc = step("vpc", lambda: ec2.create_vpc(CidrBlock="10.20.0.0/16", TagSpecifications=[
    {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "storefront"}]}]))
if vpc:
    vpc_id = vpc["Vpc"]["VpcId"]
    igw = step("igw", lambda: ec2.create_internet_gateway())
    if igw:
        step("attach igw", lambda: ec2.attach_internet_gateway(InternetGatewayId=igw["InternetGateway"]["InternetGatewayId"], VpcId=vpc_id))
    subnets = []
    for cidr, az, name in [("10.20.0.0/24", "us-east-1a", "public-a"), ("10.20.1.0/24", "us-east-1b", "public-b"),
                           ("10.20.10.0/24", "us-east-1a", "private-a"), ("10.20.11.0/24", "us-east-1b", "private-b")]:
        sn = step(name, lambda: ec2.create_subnet(VpcId=vpc_id, CidrBlock=cidr, AvailabilityZone=az, TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"storefront-{name}"}]}]))
        if sn:
            subnets.append(sn["Subnet"]["SubnetId"])
    rtb = step("rtb", lambda: ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[
        {"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": "public"}]}]))
    if rtb and igw:
        rtb_id = rtb["RouteTable"]["RouteTableId"]
        step("route", lambda: ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0",
                                              GatewayId=igw["InternetGateway"]["InternetGatewayId"]))
        for sn in subnets[:2]:
            step("assoc", lambda: ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sn))
    sg = step("sg", lambda: ec2.create_security_group(GroupName="web", Description="Web tier", VpcId=vpc_id))
    if sg:
        step("ingress", lambda: ec2.authorize_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS"}]},
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTP"}]}]))
    step("profile", lambda: iam.create_instance_profile(InstanceProfileName="web-server"))
    step("profile role", lambda: iam.add_role_to_instance_profile(InstanceProfileName="web-server", RoleName="web-server"))
    images = step("images", lambda: ec2.describe_images(Owners=["amazon"]))
    image = images["Images"][0]["ImageId"] if images and images["Images"] else "ami-12345678"
    if subnets:
        for i, name in enumerate(["web-1", "web-2"]):
            step(name, lambda: ec2.run_instances(ImageId=image, InstanceType="t3.small", MinCount=1, MaxCount=1,
                                                SubnetId=subnets[i % 2], SecurityGroupIds=[sg["GroupId"]] if sg else [],
                                                TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": f"storefront-{name}"}]}]))
        step("worker", lambda: ec2.run_instances(ImageId=image, InstanceType="m7i.large", MinCount=1, MaxCount=1, SubnetId=subnets[2],
                                                TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "storefront-worker"}]}]))

# Route 53
print("Route 53")
zone = step("zone", lambda: r53.create_hosted_zone(Name="storefront.example", CallerReference=str(time.time())))
if zone:
    zid = zone["HostedZone"]["Id"].split("/")[-1]
    step("records", lambda: r53.change_resource_record_sets(HostedZoneId=zid, ChangeBatch={"Changes": [
        {"Action": "CREATE", "ResourceRecordSet": {"Name": "www.storefront.example", "Type": "A", "TTL": 300,
                                                   "ResourceRecords": [{"Value": "203.0.113.10"}, {"Value": "203.0.113.11"}]}},
        {"Action": "CREATE", "ResourceRecordSet": {"Name": "api.storefront.example", "Type": "CNAME", "TTL": 60,
                                                   "ResourceRecords": [{"Value": "checkout.lambda-url.us-east-1.on.aws"}]}},
        {"Action": "CREATE", "ResourceRecordSet": {"Name": "storefront.example", "Type": "MX", "TTL": 3600,
                                                   "ResourceRecords": [{"Value": "10 inbound-smtp.us-east-1.amazonaws.com"}]}},
        {"Action": "CREATE", "ResourceRecordSet": {"Name": "storefront.example", "Type": "TXT", "TTL": 3600,
                                                   "ResourceRecords": [{"Value": '"v=spf1 include:amazonses.com ~all"'}]}},
    ]}))

# Private CA
print("Private CA")
ca = step("ca", lambda: pca.create_certificate_authority(CertificateAuthorityType="ROOT", CertificateAuthorityConfiguration={
    "KeyAlgorithm": "EC_prime256v1", "SigningAlgorithm": "SHA256WITHECDSA",
    "Subject": {"CommonName": "Storefront Root CA", "Organization": "Storefront", "Country": "US"}},
    Tags=[{"Key": "app", "Value": "storefront"}]))
if ca:
    ca_arn = ca["CertificateAuthorityArn"]
    time.sleep(1)
    csr = step("csr", lambda: pca.get_certificate_authority_csr(CertificateAuthorityArn=ca_arn))
    if csr:
        cert = step("issue", lambda: pca.issue_certificate(CertificateAuthorityArn=ca_arn, Csr=csr["Csr"], SigningAlgorithm="SHA256WITHECDSA",
                                                          TemplateArn="arn:aws:acm-pca:::template/RootCACertificate/V1",
                                                          Validity={"Value": 10, "Type": "YEARS"}))
        if cert:
            time.sleep(1.5)
            body = step("get", lambda: pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert["CertificateArn"]))
            if body:
                step("import", lambda: pca.import_certificate_authority_certificate(CertificateAuthorityArn=ca_arn, Certificate=body["Certificate"]))

# Kinesis
print("Kinesis")
step("stream", lambda: kinesis.create_stream(StreamName="clickstream", ShardCount=2))
time.sleep(1)
for i in range(20):
    step("record", lambda: kinesis.put_record(StreamName="clickstream", PartitionKey=f"user-{i % 5}",
                                                       Data=json.dumps({"event": ["view", "add_to_cart", "purchase"][i % 3], "sku": f"SKU-{i:04}"}).encode()))

# CloudFormation
print("CloudFormation")
template = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Storefront image pipeline",
    "Parameters": {"Stage": {"Type": "String", "Default": "prod"}},
    "Resources": {
        "Thumbnails": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": {"Fn::Sub": "storefront-thumbnails-${Stage}"}}},
        "ResizeQueue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": {"Fn::Sub": "resize-${Stage}"}}},
        "ResizeTopic": {"Type": "AWS::SNS::Topic"},
        "ConfigParam": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Name": {"Fn::Sub": "/storefront/${Stage}/thumbnail-sizes"}, "Value": "64,256,1024"}},
    },
    "Outputs": {"BucketArn": {"Value": {"Fn::GetAtt": ["Thumbnails", "Arn"]}, "Export": {"Name": "ThumbnailsBucketArn"}}},
}
step("stack", lambda: cfn.create_stack(StackName="storefront-images", TemplateBody=json.dumps(template),
                                      Tags=[{"Key": "app", "Value": "storefront"}]))

# Organizations
print("Organizations")
step("org", lambda: orgs.create_organization(FeatureSet="ALL"))
roots = step("roots", lambda: orgs.list_roots())
if roots:
    root = roots["Roots"][0]["Id"]
    for ou_name, accounts in [("Workloads", [("storefront-prod", "prod"), ("storefront-staging", "staging")]),
                              ("Security", [("log-archive", "security")])]:
        ou = step(ou_name, lambda: orgs.create_organizational_unit(ParentId=root, Name=ou_name))
        for acct, env in accounts:
            res = step(acct, lambda: orgs.create_account(AccountName=acct, Email=f"{acct}@example.com"))
            if res and ou:
                time.sleep(0.8)
                st = step("status", lambda: orgs.describe_create_account_status(CreateAccountRequestId=res["CreateAccountStatus"]["Id"]))
                acct_id = st and st["CreateAccountStatus"].get("AccountId")
                if acct_id:
                    step("move", lambda: orgs.move_account(AccountId=acct_id, SourceParentId=root,
                                                          DestinationParentId=ou["OrganizationalUnit"]["Id"]))
    scp = step("scp", lambda: orgs.create_policy(Name="DenyLeavingOrg", Type="SERVICE_CONTROL_POLICY", Description="Accounts cannot leave",
                                                Content=json.dumps({"Version": "2012-10-17", "Statement": [
                                                    {"Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"}]})))
    if scp:
        step("attach scp", lambda: orgs.attach_policy(PolicyId=scp["Policy"]["PolicySummary"]["Id"], TargetId=root))

# Named snapshots for the control plane page
import urllib.request
for name in ["baseline", "before-migration"]:
    step(name, lambda: urllib.request.urlopen(urllib.request.Request(f"{ENDPOINT}/_mws/snapshots/{name}", method="PUT")))

print("done")
