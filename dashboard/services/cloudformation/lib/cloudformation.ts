import type { Rule } from "@mws-dashboard/ui";

// CloudFormation's model leaves these unconstrained; the limits are in its
// docs (stack names, the 51,200-byte TemplateBody).
export const STACK_NAME: Rule = { pattern: "^[A-Za-z][-A-Za-z0-9]*$", maxLength: 128, hint: "Starts with a letter; letters, digits and -", generate: "name" };
export const TEMPLATE: Rule = { format: "yaml", maxLength: 51200 };
export const PARAMETERS: Rule = { format: "keyvalue" };

const enc = encodeURIComponent;
const last = (id: string) => id.split("/").pop()!;

/** AWS icons and console links for the resource types MWS deploys. Types
 * whose resources have no console page of their own get an icon only. */
const TYPES: Record<string, { icon: string; href?: (id: string) => string }> = {
  "AWS::S3::Bucket": { icon: "resource/AmazonSimpleStorageServiceBucket", href: (id) => `/s3/${enc(id)}` },
  "AWS::S3::BucketPolicy": { icon: "resource/AmazonSimpleStorageServiceBucket", href: (id) => `/s3/${enc(id)}` },
  "AWS::SQS::Queue": { icon: "resource/AmazonSimpleQueueServiceQueue", href: (id) => `/sqs/${enc(last(id))}` },
  "AWS::SNS::Topic": { icon: "resource/AmazonSimpleNotificationServiceTopic", href: (id) => `/sns/topic?arn=${enc(id)}` },
  "AWS::SNS::Subscription": { icon: "resource/AmazonSimpleNotificationServiceTopic", href: (id) => `/sns/topic?arn=${enc(id.split(":").slice(0, 6).join(":"))}` },
  "AWS::Lambda::Function": { icon: "resource/AWSLambdaLambdaFunction", href: (id) => `/lambda/${enc(id)}` },
  "AWS::Lambda::Alias": { icon: "resource/AWSLambdaLambdaFunction", href: (id) => `/lambda/${enc(id.split(":")[6] ?? id)}` },
  "AWS::Lambda::Version": { icon: "resource/AWSLambdaLambdaFunction", href: (id) => `/lambda/${enc(id.split(":")[6] ?? id)}` },
  "AWS::Lambda::Url": { icon: "resource/AWSLambdaLambdaFunction" },
  "AWS::Lambda::Permission": { icon: "resource/AWSLambdaLambdaFunction" },
  "AWS::Lambda::EventSourceMapping": { icon: "resource/AWSLambdaLambdaFunction" },
  "AWS::Lambda::LayerVersion": { icon: "resource/AWSLambdaLambdaFunction" },
  "AWS::IAM::Role": { icon: "resource/AWSIdentityAccessManagementRole", href: (id) => `/iam/roles/${enc(id)}` },
  "AWS::IAM::User": { icon: "resource/User", href: (id) => `/iam/users/${enc(id)}` },
  "AWS::IAM::Group": { icon: "resource/Users", href: (id) => `/iam/groups/${enc(id)}` },
  "AWS::IAM::Policy": { icon: "resource/AWSIdentityAccessManagementPermissions" },
  "AWS::IAM::ManagedPolicy": { icon: "resource/AWSIdentityAccessManagementPermissions", href: (id) => (id.startsWith("arn:") ? `/iam/policy?arn=${enc(id)}` : "/iam?tab=policies") },
  "AWS::IAM::InstanceProfile": { icon: "resource/AWSIdentityAccessManagementRole" },
  "AWS::IAM::AccessKey": { icon: "resource/AWSIdentityAccessManagementAddon" },
  "AWS::KMS::Key": { icon: "resource/AWSIdentityAccessManagementDataEncryptionKey", href: (id) => `/kms/key?id=${enc(id)}` },
  "AWS::KMS::Alias": { icon: "resource/AWSIdentityAccessManagementDataEncryptionKey", href: () => "/kms" },
  "AWS::SecretsManager::Secret": { icon: "service/AWSSecretsManager", href: (id) => `/secrets/secret?id=${enc(id)}` },
  "AWS::SSM::Parameter": { icon: "resource/AWSSystemsManagerParameterStore", href: (id) => `/ssm?path=${enc(id.includes("/") ? id.slice(0, id.lastIndexOf("/")) || "/" : "")}` },
  "AWS::EC2::Instance": { icon: "resource/AmazonEC2Instance", href: (id) => `/ec2/instance?id=${enc(id)}` },
  "AWS::EC2::VPC": { icon: "resource/AmazonVPCVirtualprivatecloudVPC", href: (id) => `/vpc/${enc(id)}` },
  "AWS::EC2::Subnet": { icon: "group/Privatesubnet", href: (id) => `/vpc/subnet?id=${enc(id)}` },
  "AWS::EC2::SecurityGroup": { icon: "resource/AmazonVPCNetworkAccessControlList", href: (id) => `/ec2/group?id=${enc(id)}` },
  "AWS::EC2::InternetGateway": { icon: "resource/AmazonVPCInternetGateway", href: () => "/vpc?tab=igw" },
  "AWS::EC2::NatGateway": { icon: "resource/AmazonVPCNATGateway", href: () => "/vpc?tab=nat" },
  "AWS::EC2::RouteTable": { icon: "resource/AmazonVPCRouter", href: (id) => `/vpc/rtb?id=${enc(id)}` },
  "AWS::EC2::NetworkAcl": { icon: "resource/AmazonVPCNetworkAccessControlList", href: () => "/vpc?tab=acls" },
  "AWS::EC2::KeyPair": { icon: "resource/AmazonEC2Instance", href: () => "/ec2?tab=keys" },
  "AWS::Logs::LogGroup": { icon: "resource/AmazonCloudWatchLogs", href: (id) => `/logs/group?name=${enc(id)}` },
  "AWS::CloudWatch::Alarm": { icon: "resource/AmazonCloudWatchAlarm", href: () => "/alarms" },
  "AWS::CloudWatch::CompositeAlarm": { icon: "resource/AmazonCloudWatchAlarm", href: () => "/alarms" },
  "AWS::Events::Rule": { icon: "resource/AmazonEventBridgeRule", href: (id) => (id.includes("|") ? `/events?bus=${enc(id.split("|")[0])}` : "/events") },
  "AWS::Events::EventBus": { icon: "service/AmazonEventBridge", href: (id) => `/events?bus=${enc(last(id))}` },
  "AWS::Kinesis::Stream": { icon: "service/AmazonKinesisDataStreams", href: (id) => `/kinesis/stream?name=${enc(id)}` },
  "AWS::KinesisFirehose::DeliveryStream": { icon: "service/AmazonDataFirehose", href: (id) => `/firehose/stream?name=${enc(last(id))}` },
  "AWS::Route53::HostedZone": { icon: "resource/AmazonRoute53HostedZone", href: (id) => `/route53/zone?id=${enc(last(id))}` },
  "AWS::CertificateManager::Certificate": { icon: "service/AWSCertificateManager", href: (id) => `/acm/cert?arn=${enc(id)}` },
  "AWS::ACMPCA::CertificateAuthority": { icon: "service/AWSPrivateCertificateAuthority", href: (id) => `/pca/ca?arn=${enc(id)}` },
  "AWS::CloudFormation::Stack": { icon: "resource/AWSCloudFormationStack", href: (id) => `/cloudformation/stack?name=${enc(id)}` },
};

/** The primary identifier CloudFormation imports each type by (the types
 * MWS can import). */
export const IMPORT_IDENTIFIERS: Record<string, string> = {
  "AWS::S3::Bucket": "BucketName",
  "AWS::SQS::Queue": "QueueUrl",
  "AWS::SNS::Topic": "TopicArn",
  "AWS::Lambda::Function": "FunctionName",
  "AWS::IAM::Role": "RoleName",
  "AWS::IAM::User": "UserName",
  "AWS::KMS::Key": "KeyId",
  "AWS::SSM::Parameter": "Name",
  "AWS::SecretsManager::Secret": "Id",
  "AWS::Logs::LogGroup": "LogGroupName",
  "AWS::Kinesis::Stream": "Name",
  "AWS::Route53::HostedZone": "Id",
  "AWS::EC2::VPC": "VpcId",
  "AWS::EC2::Subnet": "SubnetId",
  "AWS::EC2::SecurityGroup": "Id",
  "AWS::CloudWatch::Alarm": "AlarmName",
  "AWS::Events::Rule": "Arn",
};

/** A status word as the console shows it ("UPDATE_ROLLBACK_COMPLETE" ->
 * "update rollback complete"). */
export const word = (s: string | undefined) => (s ?? "").toLowerCase().replace(/_/g, " ");

export function resourceType(type: string | undefined) {
  return TYPES[type ?? ""] ?? { icon: "resource/AWSCloudFormationTemplate" };
}

export const SAMPLE_TEMPLATE = `AWSTemplateFormatVersion: "2010-09-09"
Description: A queue and a bucket
Parameters:
  Env:
    Type: String
    Default: dev
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub "\${AWS::StackName}-\${Env}"
  Bucket:
    Type: AWS::S3::Bucket
Outputs:
  QueueUrl:
    Value: !Ref Queue
  BucketName:
    Value: !Ref Bucket
`;
