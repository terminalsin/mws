// Common alarms, for the create-alarm sheet: each names the metric AWS
// publishes, the statistic and period people use for it, a sensible
// threshold, and the dimension that picks the resource.

export interface AlarmPreset {
  id: string;
  label: string;
  icon: string;
  title?: string;
  /** The alarm name it suggests (made unique). */
  base: string;
  namespace: string;
  metric: string;
  stat: string;
  comparison: string;
  threshold: number;
  period: number;
  evaluations: number;
  datapoints?: number;
  missing?: string;
  /** The dimension that names the resource. */
  dimension?: string;
  /** A fixed dimension value (Billing's currency). */
  dimensionValue?: string;
}

export const ALARM_PRESETS: AlarmPreset[] = [
  { id: "cpu", label: "EC2 CPU", icon: "resource/AmazonEC2Instance", title: "Average CPU above 80% for 15 minutes", base: "cpu-high", namespace: "AWS/EC2", metric: "CPUUtilization", stat: "Average", comparison: "GreaterThanThreshold", threshold: 80, period: 300, evaluations: 3, dimension: "InstanceId" },
  { id: "lambda-errors", label: "Lambda errors", icon: "resource/AWSLambdaLambdaFunction", title: "Any function error in a minute", base: "lambda-errors", namespace: "AWS/Lambda", metric: "Errors", stat: "Sum", comparison: "GreaterThanThreshold", threshold: 0, period: 60, evaluations: 1, missing: "notBreaching", dimension: "FunctionName" },
  { id: "lambda-duration", label: "Lambda latency", icon: "service/AWSLambda", title: "p99 duration above 3 s for 5 minutes", base: "lambda-slow", namespace: "AWS/Lambda", metric: "Duration", stat: "p99", comparison: "GreaterThanThreshold", threshold: 3000, period: 60, evaluations: 5, datapoints: 3, missing: "notBreaching", dimension: "FunctionName" },
  { id: "sqs-backlog", label: "Queue backlog", icon: "resource/AmazonSimpleQueueServiceQueue", title: "More than 100 messages waiting for 10 minutes", base: "queue-backlog", namespace: "AWS/SQS", metric: "ApproximateNumberOfMessagesVisible", stat: "Maximum", comparison: "GreaterThanThreshold", threshold: 100, period: 300, evaluations: 2, dimension: "QueueName" },
  { id: "sqs-dlq", label: "Dead letters", icon: "service/AmazonSimpleQueueService", title: "A dead-letter queue is not empty", base: "dead-letters", namespace: "AWS/SQS", metric: "ApproximateNumberOfMessagesVisible", stat: "Maximum", comparison: "GreaterThanThreshold", threshold: 0, period: 60, evaluations: 1, missing: "notBreaching", dimension: "QueueName" },
  { id: "alb-5xx", label: "ALB 5xx", icon: "resource/ElasticLoadBalancingApplicationLoadBalancer", title: "More than 10 server errors a minute", base: "alb-5xx", namespace: "AWS/ApplicationELB", metric: "HTTPCode_Target_5XX_Count", stat: "Sum", comparison: "GreaterThanThreshold", threshold: 10, period: 60, evaluations: 3, datapoints: 2, missing: "notBreaching", dimension: "LoadBalancer" },
  { id: "rds-storage", label: "RDS storage", icon: "service/AmazonRDS", title: "Less than 10 GB free", base: "db-storage-low", namespace: "AWS/RDS", metric: "FreeStorageSpace", stat: "Minimum", comparison: "LessThanThreshold", threshold: 10_737_418_240, period: 300, evaluations: 1, dimension: "DBInstanceIdentifier" },
  { id: "billing", label: "Billing", icon: "service/AWSCostExplorer", title: "Estimated charges above $100", base: "billing", namespace: "AWS/Billing", metric: "EstimatedCharges", stat: "Maximum", comparison: "GreaterThanThreshold", threshold: 100, period: 21600, evaluations: 1, dimension: "Currency", dimensionValue: "USD" },
];
