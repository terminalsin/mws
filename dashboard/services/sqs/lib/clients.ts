import "server-only";

import { GetQueueAttributesCommand, ListQueuesCommand, SQSClient } from "@aws-sdk/client-sqs";
import { client, collect } from "@mws-dashboard/aws";

export const sqs = () => client(SQSClient);

export const ICONS = {
  queue: "resource/AmazonSimpleQueueServiceQueue",
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
