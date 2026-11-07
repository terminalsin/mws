import "server-only";

import { EventBridgeClient } from "@aws-sdk/client-eventbridge";
import { SESv2Client } from "@aws-sdk/client-sesv2";
import { SNSClient } from "@aws-sdk/client-sns";
import { GetQueueAttributesCommand, ListQueuesCommand, SQSClient } from "@aws-sdk/client-sqs";
import { client, collect } from "@mws-dashboard/aws";

export const sqs = () => client(SQSClient);
export const sns = () => client(SNSClient);
export const events = () => client(EventBridgeClient);
export const ses = () => client(SESv2Client);

export const ICONS = {
  sqs: "service/AmazonSimpleQueueService",
  queue: "resource/AmazonSimpleQueueServiceQueue",
  sns: "service/AmazonSimpleNotificationService",
  topic: "resource/AmazonSimpleNotificationServiceTopic",
  events: "service/AmazonEventBridge",
  rule: "resource/AmazonEventBridgeRule",
  bus: "resource/AmazonEventBridgeCustomEventBus",
  defaultBus: "resource/AmazonEventBridgeDefaultEventBus",
  ses: "service/AmazonSimpleEmailService",
  email: "resource/AmazonSimpleEmailServiceEmail",
};

export function queueName(url: string) {
  return url.split("/").pop() ?? url;
}

export interface QueueInfo {
  url: string;
  name: string;
  arn: string;
  attrs: Record<string, string>;
  /** The queue this one sends failed messages to. */
  dlq?: string;
  /** Queues that send their failed messages here: this is their DLQ. */
  sources: string[];
}

/** Every queue with its attributes and the dead-letter relationships. */
export async function queues(): Promise<QueueInfo[]> {
  const client = await sqs();
  const urls = await collect(
    (NextToken) => client.send(new ListQueuesCommand({ NextToken, MaxResults: 1000 })),
    (r) => r.QueueUrls,
    (r) => r.NextToken,
  );
  const list: QueueInfo[] = await Promise.all(
    urls.map(async (url) => {
      const attrs = (await client.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ["All"] }))).Attributes ?? {};
      let dlq: string | undefined;
      try {
        dlq = attrs.RedrivePolicy ? (JSON.parse(attrs.RedrivePolicy).deadLetterTargetArn as string).split(":").pop() : undefined;
      } catch {
        // malformed policy
      }
      return { url, name: queueName(url), arn: attrs.QueueArn ?? "", attrs, dlq, sources: [] };
    }),
  );
  for (const q of list) if (q.dlq) list.find((x) => x.name === q.dlq)?.sources.push(q.name);
  return list;
}

export const isDlq = (q: QueueInfo) => q.sources.length > 0 || /(^|[-_.])(dlq|dead[-_]?letter|deadletter|failed|errors?)([-_.]|$)/i.test(q.name);
