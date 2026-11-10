// The AWS services people most often reach through a VPC endpoint, with
// their logos: the endpoint form offers them as tiles, and endpoint rows
// lead with the service's logo. Plain data, for server and client alike.

export interface KnownService {
  /** The last part of the service name: com.amazonaws.<region>.<key>. */
  key: string;
  label: string;
  icon: string;
}

export const KNOWN_SERVICES: KnownService[] = [
  { key: "s3", label: "S3", icon: "service/AmazonSimpleStorageService" },
  { key: "dynamodb", label: "DynamoDB", icon: "service/AmazonDynamoDB" },
  { key: "secretsmanager", label: "Secrets Manager", icon: "service/AWSSecretsManager" },
  { key: "ssm", label: "Systems Manager", icon: "service/AWSSystemsManager" },
  { key: "ecr.api", label: "ECR", icon: "service/AmazonElasticContainerRegistry" },
  { key: "kms", label: "KMS", icon: "service/AWSKeyManagementService" },
  { key: "sqs", label: "SQS", icon: "service/AmazonSimpleQueueService" },
  { key: "sns", label: "SNS", icon: "service/AmazonSimpleNotificationService" },
  { key: "logs", label: "CloudWatch Logs", icon: "service/AmazonCloudWatch" },
  { key: "lambda", label: "Lambda", icon: "service/AWSLambda" },
  { key: "events", label: "EventBridge", icon: "service/AmazonEventBridge" },
  { key: "kinesis-streams", label: "Kinesis", icon: "service/AmazonKinesisDataStreams" },
  { key: "ec2", label: "EC2", icon: "service/AmazonEC2" },
  { key: "ecs", label: "ECS", icon: "service/AmazonElasticContainerService" },
  { key: "bedrock-runtime", label: "Bedrock", icon: "service/AmazonBedrock" },
];

/** "com.amazonaws.us-east-1.ecr.api" → "ecr.api". */
export const serviceKey = (name: string | undefined) => (name ?? "").replace(/^com\.amazonaws\.[a-z0-9-]+\./, "");

export const knownService = (name: string | undefined) => KNOWN_SERVICES.find((s) => s.key === serviceKey(name));
