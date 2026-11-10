// Starter templates for the create-stack sheet: each is a small, working
// stack of one common shape, with outputs worth looking at.

import { SAMPLE_TEMPLATE } from "./cloudformation";

export interface StarterTemplate {
  id: string;
  label: string;
  icon: string;
  title?: string;
  /** The stack name it suggests (made unique). */
  base: string;
  body: string;
  /** Capabilities the template needs acknowledged. */
  capabilities?: string[];
}

const QUEUE = `AWSTemplateFormatVersion: "2010-09-09"
Description: A queue with a dead-letter queue
Parameters:
  MaxReceives:
    Type: Number
    Default: 5
Resources:
  DeadLetters:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: 60
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt DeadLetters.Arn
        maxReceiveCount: !Ref MaxReceives
Outputs:
  QueueUrl:
    Value: !Ref Queue
  DeadLetterQueueUrl:
    Value: !Ref DeadLetters
`;

const BUCKET = `AWSTemplateFormatVersion: "2010-09-09"
Description: A private, versioned bucket
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Enabled
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
Outputs:
  BucketName:
    Value: !Ref Bucket
  BucketArn:
    Value: !GetAtt Bucket.Arn
`;

const FANOUT = `AWSTemplateFormatVersion: "2010-09-09"
Description: A topic that fans out to a queue
Resources:
  Topic:
    Type: AWS::SNS::Topic
  Queue:
    Type: AWS::SQS::Queue
  QueuePolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [!Ref Queue]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: { Service: sns.amazonaws.com }
            Action: sqs:SendMessage
            Resource: !GetAtt Queue.Arn
            Condition:
              ArnEquals:
                aws:SourceArn: !Ref Topic
  Subscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref Topic
      Protocol: sqs
      Endpoint: !GetAtt Queue.Arn
      RawMessageDelivery: true
Outputs:
  TopicArn:
    Value: !Ref Topic
  QueueUrl:
    Value: !Ref Queue
`;

const FUNCTION = `AWSTemplateFormatVersion: "2010-09-09"
Description: A Python function with its own role and log group
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: { Service: lambda.amazonaws.com }
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  Function:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt Role.Arn
      Code:
        ZipFile: |
          def handler(event, context):
              return {"hello": event.get("name", "world")}
  Logs:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/lambda/\${Function}"
      RetentionInDays: 14
Outputs:
  FunctionName:
    Value: !Ref Function
  FunctionArn:
    Value: !GetAtt Function.Arn
`;

const VPC = `AWSTemplateFormatVersion: "2010-09-09"
Description: A VPC with two public subnets
Parameters:
  Cidr:
    Type: String
    Default: 10.0.0.0/16
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: !Ref Cidr
      EnableDnsSupport: true
      EnableDnsHostnames: true
  Gateway:
    Type: AWS::EC2::InternetGateway
  Attachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref Vpc
      InternetGatewayId: !Ref Gateway
  Routes:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref Vpc
  DefaultRoute:
    Type: AWS::EC2::Route
    DependsOn: Attachment
    Properties:
      RouteTableId: !Ref Routes
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref Gateway
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !Select [0, !Cidr [!Ref Cidr, 4, 8]]
      AvailabilityZone: !Select [0, !GetAZs ""]
      MapPublicIpOnLaunch: true
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: !Select [1, !Cidr [!Ref Cidr, 4, 8]]
      AvailabilityZone: !Select [1, !GetAZs ""]
      MapPublicIpOnLaunch: true
  RoutesA:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref SubnetA
      RouteTableId: !Ref Routes
  RoutesB:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref SubnetB
      RouteTableId: !Ref Routes
Outputs:
  VpcId:
    Value: !Ref Vpc
  SubnetIds:
    Value: !Join [",", [!Ref SubnetA, !Ref SubnetB]]
`;

const SECRET = `AWSTemplateFormatVersion: "2010-09-09"
Description: A generated database password
Resources:
  Secret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: !Sub "\${AWS::StackName}/db"
      GenerateSecretString:
        SecretStringTemplate: '{"username": "app"}'
        GenerateStringKey: password
        PasswordLength: 32
        ExcludePunctuation: true
Outputs:
  SecretArn:
    Value: !Ref Secret
`;

const BLANK = `AWSTemplateFormatVersion: "2010-09-09"
Description: An empty stack to build on
Resources:
  Placeholder:
    Type: AWS::CloudFormation::WaitConditionHandle
`;

export const STARTERS: StarterTemplate[] = [
  { id: "starter", label: "Queue + bucket", icon: "service/AWSCloudFormation", base: "starter", body: SAMPLE_TEMPLATE, title: "A queue and a bucket" },
  { id: "queue", label: "Queue + DLQ", icon: "resource/AmazonSimpleQueueServiceQueue", base: "queue", body: QUEUE, title: "SQS queue with a dead-letter queue" },
  { id: "bucket", label: "Bucket", icon: "resource/AmazonSimpleStorageServiceBucket", base: "bucket", body: BUCKET, title: "Private, versioned S3 bucket" },
  { id: "fanout", label: "Topic fan-out", icon: "resource/AmazonSimpleNotificationServiceTopic", base: "fanout", body: FANOUT, title: "SNS topic delivering to an SQS queue" },
  { id: "function", label: "Function", icon: "resource/AWSLambdaLambdaFunction", base: "function", body: FUNCTION, capabilities: ["CAPABILITY_IAM"], title: "Lambda function with a role and log group" },
  { id: "vpc", label: "VPC", icon: "resource/AmazonVPCVirtualprivatecloudVPC", base: "network", body: VPC, title: "VPC with two public subnets" },
  { id: "secret", label: "Secret", icon: "service/AWSSecretsManager", base: "secret", body: SECRET, title: "Generated Secrets Manager password" },
  { id: "blank", label: "Blank", icon: "resource/AWSCloudFormationTemplate", base: "stack", body: BLANK },
];
