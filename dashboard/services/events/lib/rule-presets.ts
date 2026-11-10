// Rule presets: the patterns people write most, filled in by the create
// form. Plain data, shared by the server page and the client form.

export interface RulePreset {
  id: string;
  label: string;
  icon: string;
  group?: string;
  title?: string;
  /** The name it suggests (made unique against the bus's rules). */
  name: string;
  pattern?: object;
  schedule?: string;
  /** Pattern and schedule both editable (the custom rule). */
  custom?: boolean;
}

export const RULE_PRESETS: RulePreset[] = [
  { id: "custom", label: "Custom", icon: "resource/AmazonEventBridgeRule", name: "rule", custom: true, title: "Your own event pattern or schedule" },
  { id: "schedule", label: "Schedule", icon: "resource/AmazonEventBridgeScheduler", name: "every-5-minutes", schedule: "rate(5 minutes)", title: "Runs the target on a rate or cron" },
  { id: "app", label: "My app's events", icon: "resource/AmazonEventBridgeEvent", name: "app-events", pattern: { source: ["my.app"] }, title: "Events your code sends with PutEvents" },
  {
    id: "s3",
    label: "S3 object created",
    icon: "service/AmazonSimpleStorageService",
    group: "AWS events",
    name: "s3-object-created",
    pattern: { source: ["aws.s3"], "detail-type": ["Object Created"] },
  },
  {
    id: "ec2",
    label: "EC2 state change",
    icon: "service/AmazonEC2",
    group: "AWS events",
    name: "ec2-state-change",
    pattern: { source: ["aws.ec2"], "detail-type": ["EC2 Instance State-change Notification"] },
  },
  {
    id: "alarm",
    label: "Alarm state change",
    icon: "service/AmazonCloudWatch",
    group: "AWS events",
    name: "alarm-state-change",
    pattern: { source: ["aws.cloudwatch"], "detail-type": ["CloudWatch Alarm State Change"], detail: { state: { value: ["ALARM"] } } },
  },
  {
    id: "ecs",
    label: "ECS task stopped",
    icon: "service/AmazonElasticContainerService",
    group: "AWS events",
    name: "ecs-task-stopped",
    pattern: { source: ["aws.ecs"], "detail-type": ["ECS Task State Change"], detail: { lastStatus: ["STOPPED"] } },
  },
  {
    id: "sfn",
    label: "Step Functions failed",
    icon: "service/AWSStepFunctions",
    group: "AWS events",
    name: "execution-failed",
    pattern: { source: ["aws.states"], "detail-type": ["Step Functions Execution Status Change"], detail: { status: ["FAILED", "TIMED_OUT", "ABORTED"] } },
  },
  {
    id: "guardduty",
    label: "GuardDuty finding",
    icon: "service/AmazonGuardDuty",
    group: "AWS events",
    name: "guardduty-finding",
    pattern: { source: ["aws.guardduty"], "detail-type": ["GuardDuty Finding"] },
  },
  {
    id: "cloudtrail",
    label: "API call",
    icon: "service/AWSCloudTrail",
    group: "AWS events",
    name: "api-call",
    title: "An AWS API call recorded by CloudTrail",
    pattern: { source: ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"], detail: { eventName: ["CreateUser"] } },
  },
];
