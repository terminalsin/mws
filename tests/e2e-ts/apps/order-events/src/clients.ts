import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import { EventBridgeClient } from "@aws-sdk/client-eventbridge";
import { IAMClient } from "@aws-sdk/client-iam";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { SQSClient } from "@aws-sdk/client-sqs";

export const events = new EventBridgeClient({});
export const iam = new IAMClient({});
export const lambda = new LambdaClient({});
export const logs = new CloudWatchLogsClient({});
export const sqs = new SQSClient({});
