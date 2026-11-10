// The events people match most, for the pattern builder: each source with
// its logo, its detail types, the fields worth filtering on (with an
// example value) and a sample event the live test runs against. Plain data.

export interface EventField {
  /** Path under the event, e.g. "detail.bucket.name". */
  path: string;
  example: string;
  /** A number, so the builder offers numeric comparisons. */
  numeric?: boolean;
}

export interface EventType {
  detailType: string;
  fields: EventField[];
  detail: object;
}

export interface EventSource {
  source: string;
  label: string;
  icon: string;
  types: EventType[];
}

export const EVENT_SOURCES: EventSource[] = [
  {
    source: "aws.s3",
    label: "S3",
    icon: "service/AmazonSimpleStorageService",
    types: [
      {
        detailType: "Object Created",
        fields: [
          { path: "detail.bucket.name", example: "uploads" },
          { path: "detail.object.key", example: "images/cat.png" },
          { path: "detail.object.size", example: "1024", numeric: true },
          { path: "detail.reason", example: "PutObject" },
        ],
        detail: { version: "0", bucket: { name: "uploads" }, object: { key: "images/cat.png", size: 1024, etag: "d41d8cd98f00b204e9800998ecf8427e" }, reason: "PutObject" },
      },
      {
        detailType: "Object Deleted",
        fields: [
          { path: "detail.bucket.name", example: "uploads" },
          { path: "detail.object.key", example: "images/cat.png" },
          { path: "detail.deletion-type", example: "Permanently Deleted" },
        ],
        detail: { version: "0", bucket: { name: "uploads" }, object: { key: "images/cat.png" }, "deletion-type": "Permanently Deleted" },
      },
    ],
  },
  {
    source: "aws.ec2",
    label: "EC2",
    icon: "service/AmazonEC2",
    types: [
      {
        detailType: "EC2 Instance State-change Notification",
        fields: [
          { path: "detail.state", example: "stopped" },
          { path: "detail.instance-id", example: "i-0123456789abcdef0" },
        ],
        detail: { "instance-id": "i-0123456789abcdef0", state: "stopped" },
      },
    ],
  },
  {
    source: "aws.cloudwatch",
    label: "CloudWatch",
    icon: "service/AmazonCloudWatch",
    types: [
      {
        detailType: "CloudWatch Alarm State Change",
        fields: [
          { path: "detail.alarmName", example: "high-cpu" },
          { path: "detail.state.value", example: "ALARM" },
          { path: "detail.previousState.value", example: "OK" },
        ],
        detail: { alarmName: "high-cpu", state: { value: "ALARM", reason: "Threshold Crossed" }, previousState: { value: "OK" } },
      },
    ],
  },
  {
    source: "aws.ecs",
    label: "ECS",
    icon: "service/AmazonElasticContainerService",
    types: [
      {
        detailType: "ECS Task State Change",
        fields: [
          { path: "detail.lastStatus", example: "STOPPED" },
          { path: "detail.clusterArn", example: "arn:aws:ecs:us-east-1:123456789012:cluster/default" },
          { path: "detail.stopCode", example: "EssentialContainerExited" },
        ],
        detail: { lastStatus: "STOPPED", desiredStatus: "STOPPED", clusterArn: "arn:aws:ecs:us-east-1:123456789012:cluster/default", stopCode: "EssentialContainerExited" },
      },
    ],
  },
  {
    source: "aws.autoscaling",
    label: "Auto Scaling",
    icon: "resource/AmazonEC2AutoScaling",
    types: [
      {
        detailType: "EC2 Instance Launch Successful",
        fields: [
          { path: "detail.AutoScalingGroupName", example: "web" },
          { path: "detail.EC2InstanceId", example: "i-0123456789abcdef0" },
        ],
        detail: { AutoScalingGroupName: "web", EC2InstanceId: "i-0123456789abcdef0", StatusCode: "InProgress" },
      },
      {
        detailType: "EC2 Instance Terminate Successful",
        fields: [{ path: "detail.AutoScalingGroupName", example: "web" }],
        detail: { AutoScalingGroupName: "web", EC2InstanceId: "i-0123456789abcdef0" },
      },
    ],
  },
  {
    source: "aws.acm",
    label: "ACM",
    icon: "service/AWSCertificateManager",
    types: [
      {
        detailType: "ACM Certificate Approaching Expiration",
        fields: [
          { path: "detail.DaysToExpiry", example: "30", numeric: true },
          { path: "detail.CommonName", example: "example.com" },
        ],
        detail: { DaysToExpiry: 30, CommonName: "example.com" },
      },
    ],
  },
  {
    source: "aws.ssm",
    label: "Systems Manager",
    icon: "service/AWSSystemsManager",
    types: [
      {
        detailType: "Parameter Store Change",
        fields: [
          { path: "detail.name", example: "/app/feature-flag" },
          { path: "detail.operation", example: "Update" },
          { path: "detail.type", example: "String" },
        ],
        detail: { name: "/app/feature-flag", operation: "Update", type: "String" },
      },
    ],
  },
  {
    source: "aws.states",
    label: "Step Functions",
    icon: "service/AWSStepFunctions",
    types: [
      {
        detailType: "Step Functions Execution Status Change",
        fields: [
          { path: "detail.status", example: "FAILED" },
          { path: "detail.stateMachineArn", example: "arn:aws:states:us-east-1:123456789012:stateMachine:orders" },
        ],
        detail: { status: "FAILED", stateMachineArn: "arn:aws:states:us-east-1:123456789012:stateMachine:orders" },
      },
    ],
  },
  {
    source: "aws.guardduty",
    label: "GuardDuty",
    icon: "service/AmazonGuardDuty",
    types: [
      {
        detailType: "GuardDuty Finding",
        fields: [
          { path: "detail.severity", example: "7", numeric: true },
          { path: "detail.type", example: "UnauthorizedAccess:EC2/SSHBruteForce" },
        ],
        detail: { severity: 7, type: "UnauthorizedAccess:EC2/SSHBruteForce" },
      },
    ],
  },
  {
    source: "aws.securityhub",
    label: "Security Hub",
    icon: "service/AWSSecurityHub",
    types: [
      {
        detailType: "Security Hub Findings - Imported",
        fields: [{ path: "detail.findings.Severity.Label", example: "CRITICAL" }],
        detail: { findings: [{ Severity: { Label: "CRITICAL" }, Title: "S3 bucket is public" }] },
      },
    ],
  },
  {
    source: "aws.iam",
    label: "API calls",
    icon: "service/AWSCloudTrail",
    types: [
      {
        detailType: "AWS API Call via CloudTrail",
        fields: [
          { path: "detail.eventSource", example: "iam.amazonaws.com" },
          { path: "detail.eventName", example: "CreateUser" },
          { path: "detail.userIdentity.type", example: "IAMUser" },
        ],
        detail: { eventSource: "iam.amazonaws.com", eventName: "CreateUser", userIdentity: { type: "IAMUser" } },
      },
    ],
  },
  {
    source: "my.app",
    label: "My app",
    icon: "resource/AmazonEventBridgeEvent",
    types: [
      {
        detailType: "order.placed",
        fields: [
          { path: "detail.orderId", example: "o-123" },
          { path: "detail.total", example: "42.5", numeric: true },
          { path: "detail.customer.tier", example: "gold" },
        ],
        detail: { orderId: "o-123", total: 42.5, customer: { tier: "gold" } },
      },
    ],
  },
];

export const sourceInfo = (source: string) => EVENT_SOURCES.find((s) => s.source === source);
