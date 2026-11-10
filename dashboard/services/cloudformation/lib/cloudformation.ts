import type { Rule } from "@mws-dashboard/ui";

// CloudFormation's model leaves these unconstrained; the limits are in its
// docs (stack names, the 51,200-byte TemplateBody).
export const STACK_NAME: Rule = { pattern: "^[A-Za-z][-A-Za-z0-9]*$", maxLength: 128, hint: "Starts with a letter; letters, digits and -", generate: "name" };
export const TEMPLATE: Rule = { format: "yaml", maxLength: 51200 };
export const PARAMETERS: Rule = { format: "keyvalue" };

/** AWS icons and console links for common CloudFormation resource types. */
const TYPES: Record<string, { icon: string; href?: (id: string) => string }> = {
  "AWS::S3::Bucket": { icon: "resource/AmazonSimpleStorageServiceBucket", href: (id) => `/s3/${encodeURIComponent(id)}` },
  "AWS::SQS::Queue": { icon: "resource/AmazonSimpleQueueServiceQueue", href: (id) => `/sqs/${encodeURIComponent(id.split("/").pop()!)}` },
  "AWS::SNS::Topic": { icon: "resource/AmazonSimpleNotificationServiceTopic", href: (id) => `/sns/topic?arn=${encodeURIComponent(id)}` },
  "AWS::Lambda::Function": { icon: "resource/AWSLambdaLambdaFunction", href: (id) => `/lambda/${encodeURIComponent(id)}` },
  "AWS::IAM::Role": { icon: "resource/AWSIdentityAccessManagementRole", href: (id) => `/iam/roles/${encodeURIComponent(id)}` },
  "AWS::IAM::User": { icon: "resource/User", href: (id) => `/iam/users/${encodeURIComponent(id)}` },
  "AWS::IAM::Policy": { icon: "resource/AWSIdentityAccessManagementPermissions" },
  "AWS::IAM::ManagedPolicy": { icon: "resource/AWSIdentityAccessManagementPermissions" },
  "AWS::KMS::Key": { icon: "resource/AWSIdentityAccessManagementDataEncryptionKey", href: (id) => `/kms/key?id=${encodeURIComponent(id)}` },
  "AWS::SecretsManager::Secret": { icon: "service/AWSSecretsManager" },
  "AWS::SSM::Parameter": { icon: "resource/AWSSystemsManagerParameterStore" },
  "AWS::DynamoDB::Table": { icon: "service/AmazonDynamoDB" },
  "AWS::EC2::Instance": { icon: "resource/AmazonEC2Instance", href: (id) => `/ec2/instance?id=${id}` },
  "AWS::EC2::VPC": { icon: "resource/AmazonVPCVirtualprivatecloudVPC", href: (id) => `/vpc/${id}` },
  "AWS::EC2::Subnet": { icon: "group/Privatesubnet" },
  "AWS::EC2::SecurityGroup": { icon: "resource/AmazonVPCNetworkAccessControlList" },
  "AWS::EC2::InternetGateway": { icon: "resource/AmazonVPCInternetGateway" },
  "AWS::EC2::RouteTable": { icon: "resource/AmazonVPCRouter" },
  "AWS::Logs::LogGroup": { icon: "resource/AmazonCloudWatchLogs", href: (id) => `/logs/group?name=${encodeURIComponent(id)}` },
  "AWS::CloudWatch::Alarm": { icon: "resource/AmazonCloudWatchAlarm" },
  "AWS::Events::Rule": { icon: "resource/AmazonEventBridgeRule" },
  "AWS::Kinesis::Stream": { icon: "service/AmazonKinesisDataStreams", href: (id) => `/kinesis/stream?name=${encodeURIComponent(id)}` },
  "AWS::ECR::Repository": { icon: "resource/AmazonElasticContainerRegistryRegistry", href: (id) => `/ecr/repo?name=${encodeURIComponent(id)}` },
  "AWS::ECS::Cluster": { icon: "service/AmazonElasticContainerService" },
  "AWS::RDS::DBInstance": { icon: "service/AmazonRDS", href: (id) => `/rds/db?id=${encodeURIComponent(id)}` },
  "AWS::Route53::HostedZone": { icon: "resource/AmazonRoute53HostedZone" },
  "AWS::ElasticLoadBalancingV2::LoadBalancer": { icon: "resource/ElasticLoadBalancingApplicationLoadBalancer", href: (id) => `/elb/lb?arn=${encodeURIComponent(id)}` },
  "AWS::CloudFormation::Stack": { icon: "resource/AWSCloudFormationStack" },
};

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
