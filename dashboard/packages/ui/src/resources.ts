// The resource kinds the console's pickers can list (see `ResourcePicker`
// in ./pickers.tsx and `/api/resources`): what each is called, its icon,
// which value a field usually wants from it, and whether the picker can make
// one in place from just a name. Plain data, safe on server and client.

export type ResourceKind =
  | "iam-role"
  | "iam-policy"
  | "iam-user"
  | "iam-group"
  | "iam-instance-profile"
  | "kms-key"
  | "sns-topic"
  | "sqs-queue"
  | "s3-bucket"
  | "lambda-function"
  | "log-group"
  | "kinesis-stream"
  | "firehose-stream"
  | "secret"
  | "ssm-parameter"
  | "private-ca"
  | "certificate"
  | "event-bus"
  | "vpc"
  | "subnet"
  | "security-group"
  | "ec2-instance"
  | "ecr-repository"
  | "target-group"
  | "load-balancer";

/** Which value of a resource a field takes. */
export type ResourceValue = "arn" | "name" | "id" | "url";

export interface ResourceKindInfo {
  noun: string;
  icon: string;
  /** The value a field takes when the page does not say. */
  value: ResourceValue;
  /** The picker can create one from a name (see `/api/resources` POST). */
  create?: { label: string; pattern?: string; hint?: string };
  /** Where the resource's list lives, for "Open in console". */
  href?: string;
}

export const RESOURCE_KINDS: Record<ResourceKind, ResourceKindInfo> = {
  "iam-role": { noun: "role", icon: "resource/AWSIdentityAccessManagementRole", value: "arn", create: { label: "New role", pattern: "^[\\w+=,.@-]{1,64}$" }, href: "/iam?tab=roles" },
  "iam-policy": { noun: "policy", icon: "resource/AWSIdentityAccessManagementPermissions", value: "arn", href: "/iam?tab=policies" },
  "iam-user": { noun: "user", icon: "resource/User", value: "arn", href: "/iam" },
  "iam-group": { noun: "group", icon: "resource/Users", value: "name", href: "/iam?tab=groups" },
  "iam-instance-profile": { noun: "instance profile", icon: "resource/AWSIdentityAccessManagementRole", value: "arn", href: "/iam?tab=roles" },
  "kms-key": { noun: "key", icon: "resource/AWSIdentityAccessManagementDataEncryptionKey", value: "arn", create: { label: "New key", pattern: "^[a-zA-Z0-9/_-]{1,250}$", hint: "Alias for a new symmetric key" }, href: "/kms" },
  "sns-topic": { noun: "topic", icon: "resource/AmazonSimpleNotificationServiceTopic", value: "arn", create: { label: "New topic", pattern: "^[\\w-]{1,256}(\\.fifo)?$" }, href: "/sns" },
  "sqs-queue": { noun: "queue", icon: "resource/AmazonSimpleQueueServiceQueue", value: "arn", create: { label: "New queue", pattern: "^[\\w-]{1,80}(\\.fifo)?$" }, href: "/sqs" },
  "s3-bucket": { noun: "bucket", icon: "resource/AmazonSimpleStorageServiceBucket", value: "name", create: { label: "New bucket", pattern: "^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$" }, href: "/s3" },
  "lambda-function": { noun: "function", icon: "resource/AWSLambdaLambdaFunction", value: "arn", href: "/lambda" },
  "log-group": { noun: "log group", icon: "resource/AmazonCloudWatchLogs", value: "name", create: { label: "New log group", pattern: "^[\\w#/.-]{1,512}$" }, href: "/logs" },
  "kinesis-stream": { noun: "data stream", icon: "service/AmazonKinesisDataStreams", value: "arn", create: { label: "New on-demand stream", pattern: "^[\\w.-]{1,128}$" }, href: "/kinesis" },
  "firehose-stream": { noun: "Firehose stream", icon: "service/AmazonDataFirehose", value: "arn", href: "/firehose" },
  secret: { noun: "secret", icon: "service/AWSSecretsManager", value: "arn", href: "/secrets" },
  "ssm-parameter": { noun: "parameter", icon: "resource/AWSSystemsManagerParameterStore", value: "name", href: "/ssm" },
  "private-ca": { noun: "certificate authority", icon: "resource/AWSCertificateManagerCertificateAuthority", value: "arn", href: "/pca" },
  certificate: { noun: "certificate", icon: "service/AWSCertificateManager", value: "arn", href: "/acm" },
  "event-bus": { noun: "event bus", icon: "resource/AmazonEventBridgeCustomEventBus", value: "arn", create: { label: "New event bus", pattern: "^[\\w.-]{1,256}$" }, href: "/events" },
  vpc: { noun: "VPC", icon: "resource/AmazonVPCVirtualprivatecloudVPC", value: "id", href: "/vpc" },
  subnet: { noun: "subnet", icon: "group/Privatesubnet", value: "id", href: "/vpc" },
  "security-group": { noun: "security group", icon: "resource/AmazonVPCNetworkAccessControlList", value: "id", href: "/ec2?tab=groups" },
  "ec2-instance": { noun: "instance", icon: "resource/AmazonEC2Instance", value: "id", href: "/ec2" },
  "ecr-repository": { noun: "repository", icon: "resource/AmazonElasticContainerRegistryRegistry", value: "name", href: "/ecr" },
  "target-group": { noun: "target group", icon: "resource/ElasticLoadBalancingApplicationLoadBalancer", value: "arn", href: "/elb" },
  "load-balancer": { noun: "load balancer", icon: "resource/ElasticLoadBalancingApplicationLoadBalancer", value: "arn", href: "/elb" },
};

export const isResourceKind = (k: string): k is ResourceKind => k in RESOURCE_KINDS;

/** One resource as a picker shows it. */
export interface ResourceOption {
  kind: ResourceKind;
  name: string;
  arn?: string;
  id?: string;
  url?: string;
  /** A short fact: a description, CIDR, state, "AWS managed". */
  detail?: string;
  /** Section in the list ("Trusts lambda.amazonaws.com", "AWS managed"). */
  group?: string;
  /** For roles: the service principals the trust policy names. */
  services?: string[];
  /** For VPC-scoped kinds: the VPC it belongs to. */
  vpc?: string;
  /** Other strings the search should match (aliases, tags). */
  also?: string[];
}

/** The value a field takes from an option. */
export function optionValue(o: ResourceOption, want?: ResourceValue): string {
  const w = want ?? RESOURCE_KINDS[o.kind].value;
  return (w === "arn" ? o.arn : w === "id" ? o.id : w === "url" ? o.url : o.name) ?? o.arn ?? o.id ?? o.name;
}

/** Every value an option could be written as, for recognizing a typed one. */
export function optionValues(o: ResourceOption): string[] {
  return [o.arn, o.id, o.url, o.name, ...(o.also ?? [])].filter((v): v is string => !!v);
}
