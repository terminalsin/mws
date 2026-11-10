"use server";

import { CreateTopicCommand, DeleteTopicCommand, PublishCommand, SubscribeCommand, UnsubscribeCommand } from "@aws-sdk/client-sns";
import { GetQueueAttributesCommand, GetQueueUrlCommand, SetQueueAttributesCommand } from "@aws-sdk/client-sqs";
import { act, FieldError, mws, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { sns, sqs } from "../../lib/clients";

// SNS reports bad input as `InvalidParameter: Invalid parameter: <what>
// [Reason: <why>]`, naming the parameter in words rather than as a member
// path. These map each to the form field it concerns, with a short message
// for when SNS gives no reason.
const PARAMETERS: [RegExp, string, string][] = [
  [/^Topic Name/, "name", "Letters, digits, - and _; FIFO topics end in .fifo"],
  [/^Attributes Reason: Topic already exists/, "name", "Exists with different settings"],
  [/^Invalid protocol type/, "protocol", "Not available for this topic"],
  [/^(Endpoint|Email address|SQS endpoint ARN|Lambda endpoint ARN|Firehose endpoint ARN|Invalid SMS endpoint|Application endpoint arn)/, "endpoint", "Does not match the protocol"],
  [/^SubscriptionRoleArn/, "role", "Required for Firehose"],
  [/^Subject/, "subject", "ASCII, no leading space, under 100 characters"],
  [/^(Empty message|Message too long)/, "message", "Empty or over 256 KB"],
  [/MessageGroupId/, "group", "Letters, digits and punctuation"],
  [/^MessageDeduplicationId/, "dedup", "Letters, digits and punctuation"],
];

/** Run an SNS call, turning a parameter error into an error on its field. */
async function onFields<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (e) {
    const what = e instanceof Error ? e.message.match(/^(?:Invalid parameter: )+(.*)$/s)?.[1] : undefined;
    const hit = what ? PARAMETERS.find(([re]) => re.test(what)) : undefined;
    if (!hit) throw e;
    const [, field, fallback] = hit;
    const reason = what!.match(/Reason: (.*)$/s)?.[1];
    const taken = field === "name" && /already exists/.test(what!);
    throw new FieldError(field, taken ? fallback : reason || fallback, taken ? "taken" : "server");
  }
}

/** Add a statement to the queue's access policy that lets the topic send to
 * it, as the AWS console does when it subscribes a queue. Without it SNS
 * cannot deliver (SQS checks the queue policy for service principals). */
async function allowTopicOnQueue(topicArn: string, queueArn: string) {
  const [, , , , account, name] = queueArn.split(":");
  const client = await sqs();
  const QueueUrl = await client
    .send(new GetQueueUrlCommand({ QueueName: name, QueueOwnerAWSAccountId: account }))
    .then((r) => r.QueueUrl!)
    .catch((e: unknown) => {
      if (e instanceof Error && /QueueDoesNotExist|NonExistentQueue/.test(e.name)) throw new FieldError("endpoint", "No such queue", "missing");
      throw e;
    });
  const current = (await client.send(new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ["Policy"] }))).Attributes?.Policy;
  const policy = current ? JSON.parse(current) : { Version: "2012-10-17", Statement: [] };
  const sid = `topic-${topicArn.split(":").pop()}`.replace(/[^A-Za-z0-9]/g, "").slice(0, 100);
  policy.Statement = [
    ...(policy.Statement ?? []).filter((s: { Sid?: string }) => s.Sid !== sid),
    {
      Sid: sid,
      Effect: "Allow",
      Principal: { Service: "sns.amazonaws.com" },
      Action: "sqs:SendMessage",
      Resource: queueArn,
      Condition: { ArnEquals: { "aws:SourceArn": topicArn } },
    },
  ];
  await client.send(new SetQueueAttributesCommand({ QueueUrl, Attributes: { Policy: JSON.stringify(policy) } }));
}

export async function createTopic(_: ActionResult | null, form: FormData) {
  return act(async () => {
    let name = required(form, "name", "Topic name");
    const fifo = text(form, "fifo") === "on";
    if (fifo && !name.endsWith(".fifo")) name += ".fifo";
    const client = await sns();
    const out = await onFields(() =>
      client.send(new CreateTopicCommand({ Name: name, ...(fifo ? { Attributes: { FifoTopic: "true", ContentBasedDeduplication: "true" } } : {}) })),
    );
    return `Created ${out.TopicArn}`;
  }, { revalidate: ["/sns"], fields: { Name: "name" } });
}

export async function publish(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const subject = text(form, "subject");
    const group = text(form, "group");
    const dedup = text(form, "dedup");
    const message = required(form, "message", "Message");
    const client = await sns();
    const out = await onFields(() =>
      client.send(
        new PublishCommand({
          TopicArn: arn,
          Message: message,
          ...(subject ? { Subject: subject } : {}),
          ...(group ? { MessageGroupId: group } : {}),
          ...(dedup ? { MessageDeduplicationId: dedup } : {}),
        }),
      ),
    );
    return `Published ${out.MessageId}`;
  }, { revalidate: ["/sns/topic"], fields: { Subject: "subject", MessageGroupId: "group", MessageDeduplicationId: "dedup" } });
}

export async function subscribe(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = required(form, "protocol", "Protocol");
    const endpoint = required(form, "endpoint", "Endpoint");
    const role = protocol === "firehose" ? required(form, "role", "Subscription role") : "";
    const grant = protocol === "sqs" && text(form, "grant") === "on";
    if (grant) await allowTopicOnQueue(arn, endpoint);
    const client = await sns();
    const out = await onFields(() =>
      client.send(
        new SubscribeCommand({
          TopicArn: arn,
          Protocol: protocol,
          Endpoint: endpoint,
          ReturnSubscriptionArn: true,
          ...(role ? { Attributes: { SubscriptionRoleArn: role } } : {}),
        }),
      ),
    );
    return `Subscribed: ${out.SubscriptionArn}${grant ? " (and allowed the topic in the queue policy)" : ""}`;
  }, { revalidate: ["/sns/topic"], fields: { Endpoint: "endpoint", Protocol: "protocol", SubscriptionRoleArn: "role" } });
}

export async function unsubscribe(subscriptionArn: string) {
  return act(async () => {
    await (await sns()).send(new UnsubscribeCommand({ SubscriptionArn: subscriptionArn }));
    return "Unsubscribed";
  }, "/sns/topic");
}

export async function deleteTopic(arn: string) {
  return act(async () => {
    await (await sns()).send(new DeleteTopicCommand({ TopicArn: arn }));
    redirect("/sns");
  });
}

export async function clearOutbox(kind: "email-messages" | "sms-messages") {
  return act(async () => {
    await mws(`/_aws/sns/${kind}`, { method: "DELETE" });
    return "Cleared";
  }, "/sns");
}

