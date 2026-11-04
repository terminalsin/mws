import { CloudWatchClient } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import { SNSClient } from "@aws-sdk/client-sns";
import { SQSClient } from "@aws-sdk/client-sqs";

export const cloudwatch = new CloudWatchClient({});
export const logs = new CloudWatchLogsClient({});
export const sns = new SNSClient({});
export const sqs = new SQSClient({});
