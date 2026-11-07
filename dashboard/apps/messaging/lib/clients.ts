import "server-only";

import { EventBridgeClient } from "@aws-sdk/client-eventbridge";
import { SESv2Client } from "@aws-sdk/client-sesv2";
import { SNSClient } from "@aws-sdk/client-sns";
import { SQSClient } from "@aws-sdk/client-sqs";
import { client } from "@mws-dashboard/aws";

export const sqs = () => client(SQSClient);
export const sns = () => client(SNSClient);
export const events = () => client(EventBridgeClient);
export const ses = () => client(SESv2Client);

export function queueName(url: string) {
  return url.split("/").pop() ?? url;
}
