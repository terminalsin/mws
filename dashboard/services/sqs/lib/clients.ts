import "server-only";

import { EventBridgeClient, ListEventBusesCommand, ListRuleNamesByTargetCommand } from "@aws-sdk/client-eventbridge";
import { IAMClient } from "@aws-sdk/client-iam";
import { LambdaClient, ListEventSourceMappingsCommand, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { ListSubscriptionsCommand, SNSClient } from "@aws-sdk/client-sns";
import {
  GetQueueAttributesCommand,
  GetQueueUrlCommand,
  ListDeadLetterSourceQueuesCommand,
  ListMessageMoveTasksCommand,
  ListQueuesCommand,
  ListQueueTagsCommand,
  SQSClient,
} from "@aws-sdk/client-sqs";
import { all, client } from "@mws-dashboard/aws";

export const sqs = () => client(SQSClient);
export const lambda = () => client(LambdaClient);
export const iam = () => client(IAMClient);

export const ICONS = {
  queue: "resource/AmazonSimpleQueueServiceQueue",
  message: "resource/AmazonSimpleQueueServiceMessage",
};

export function queueName(url: string) {
  return url.split("/").pop() ?? url;
}

export interface QueueInfo {
  url: string;
  name: string;
  arn: string;
  attrs: Record<string, string>;
  /** The ARN of the queue this one sends failed messages to. */
  dlq?: string;
  /** ARNs of the queues that send their failed messages here: this is their DLQ. */
  sources: string[];
}

export function redriveTarget(attrs: Record<string, string>): { arn: string; maxReceiveCount: number } | undefined {
  try {
    if (!attrs.RedrivePolicy) return undefined;
    const p = JSON.parse(attrs.RedrivePolicy);
    return { arn: p.deadLetterTargetArn as string, maxReceiveCount: Number(p.maxReceiveCount) };
  } catch {
    return undefined;
  }
}

/** Every queue with its attributes and the dead-letter relationships,
 * matched by ARN (a dead-letter queue is one a redrive policy names). */
export async function queues(): Promise<QueueInfo[]> {
  const c = await sqs();
  const urls = await all(
    (NextToken) => c.send(new ListQueuesCommand({ NextToken, MaxResults: 1000 })),
    (r) => r.QueueUrls,
    (r) => r.NextToken,
  );
  const list: QueueInfo[] = await Promise.all(
    urls.map(async (url) => {
      const attrs: Record<string, string> = (await c.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ["All"] })).catch(() => undefined))?.Attributes ?? {};
      return { url, name: queueName(url), arn: attrs.QueueArn ?? "", attrs, dlq: redriveTarget(attrs)?.arn, sources: [] };
    }),
  );
  for (const q of list) if (q.dlq) list.find((x) => x.arn === q.dlq)?.sources.push(q.arn);
  return list;
}

export const isDlq = (q: { sources: string[] }) => q.sources.length > 0;

/** One queue, read directly: its attributes, tags, the queues that use it as
 * their dead-letter queue (`ListDeadLetterSourceQueues`) and redrive tasks. */
export async function queue(name: string) {
  const c = await sqs();
  const { QueueUrl } = await c.send(new GetQueueUrlCommand({ QueueName: name }));
  const [attrs, tags, sourceUrls] = await Promise.all([
    c.send(new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ["All"] })).then((r) => r.Attributes ?? {}),
    c.send(new ListQueueTagsCommand({ QueueUrl })).then((r) => r.Tags ?? {}, () => ({}) as Record<string, string>),
    all((NextToken) => c.send(new ListDeadLetterSourceQueuesCommand({ QueueUrl, NextToken, MaxResults: 1000 })), (r) => r.queueUrls, (r) => r.NextToken).catch(() => [] as string[]),
  ]);
  const arn = attrs.QueueArn ?? "";
  const [partition, region] = [arn.split(":")[1], arn.split(":")[3]];
  const sources = sourceUrls.map((u) => {
    const [account, n] = u.split("/").slice(-2);
    return `arn:${partition}:sqs:${region}:${account}:${n}`;
  });
  const tasks = sources.length
    ? await c
        .send(new ListMessageMoveTasksCommand({ SourceArn: arn, MaxResults: 10 }))
        .then((r) => r.Results ?? [])
        .catch(() => [])
    : [];
  return { url: QueueUrl!, name, arn, attrs, tags, sources, tasks, dlq: redriveTarget(attrs) };
}

/** What reads from and writes to the queue: Lambda triggers, SNS
 * subscriptions and EventBridge rules (each list is empty when the caller
 * may not read it). */
export async function neighbours(arn: string) {
  const [mappings, subscriptions, rules] = await Promise.all([
    lambda()
      .then((l) => all((Marker) => l.send(new ListEventSourceMappingsCommand({ EventSourceArn: arn, Marker })), (r) => r.EventSourceMappings, (r) => r.NextMarker))
      .catch(() => []),
    client(SNSClient)
      .then((s) => all((NextToken) => s.send(new ListSubscriptionsCommand({ NextToken })), (r) => r.Subscriptions, (r) => r.NextToken))
      .then((subs) => subs.filter((s) => s.Endpoint === arn), () => []),
    client(EventBridgeClient)
      .then(async (e) => {
        const buses = await all((NextToken) => e.send(new ListEventBusesCommand({ NextToken })), (r) => r.EventBuses, (r) => r.NextToken);
        const names = await Promise.all(
          buses.map((b) =>
            all((NextToken) => e.send(new ListRuleNamesByTargetCommand({ TargetArn: arn, EventBusName: b.Name, NextToken })), (r) => r.RuleNames, (r) => r.NextToken).then((n) =>
              n.map((rule) => ({ bus: b.Name!, rule })),
            ),
          ),
        );
        return names.flat();
      })
      .catch(() => []),
  ]);
  return { mappings, subscriptions, rules };
}

export async function functionArns() {
  const l = await lambda();
  return all((Marker) => l.send(new ListFunctionsCommand({ Marker })), (r) => r.Functions, (r) => r.NextMarker).then((f) => f.map((x) => ({ name: x.FunctionName!, arn: x.FunctionArn! })));
}
