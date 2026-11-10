import "server-only";

import { SNSClient } from "@aws-sdk/client-sns";
import { SQSClient } from "@aws-sdk/client-sqs";
import { client } from "@mws-dashboard/aws";

export const sqs = () => client(SQSClient);
export const sns = () => client(SNSClient);
export const ICONS = {
  topic: "resource/AmazonSimpleNotificationServiceTopic",
};
