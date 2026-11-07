"use server";

import { CreateTopicCommand, DeleteTopicCommand, PublishCommand, SubscribeCommand, UnsubscribeCommand } from "@aws-sdk/client-sns";
import { GetQueueAttributesCommand, GetQueueUrlCommand, SetQueueAttributesCommand } from "@aws-sdk/client-sqs";
import { act, mws, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { sns, sqs } from "../../lib/clients";

/** Add a statement to the queue's access policy that lets the topic send to
 * it, as the AWS console does when it subscribes a queue. Without it SNS
 * cannot deliver (SQS checks the queue policy for service principals). */
async function allowTopicOnQueue(topicArn: string, queueArn: string) {
  const [, , , , account, name] = queueArn.split(":");
  const client = await sqs();
  const QueueUrl = (await client.send(new GetQueueUrlCommand({ QueueName: name, QueueOwnerAWSAccountId: account }))).QueueUrl!;
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
    const out = await (await sns()).send(
      new CreateTopicCommand({ Name: name, ...(fifo ? { Attributes: { FifoTopic: "true", ContentBasedDeduplication: "true" } } : {}) }),
    );
    return `Created ${out.TopicArn}`;
  }, "/sns");
}

export async function publish(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const subject = text(form, "subject");
    const group = text(form, "group");
    const out = await (await sns()).send(
      new PublishCommand({
        TopicArn: arn,
        Message: required(form, "message", "Message"),
        ...(subject ? { Subject: subject } : {}),
        ...(group ? { MessageGroupId: group } : {}),
      }),
    );
    return `Published ${out.MessageId}`;
  }, "/sns/topic");
}

export async function subscribe(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = required(form, "protocol", "Protocol");
    const endpoint = required(form, "endpoint", "Endpoint");
    const grant = protocol === "sqs" && text(form, "grant") === "on";
    if (grant) await allowTopicOnQueue(arn, endpoint);
    const out = await (await sns()).send(
      new SubscribeCommand({ TopicArn: arn, Protocol: protocol, Endpoint: endpoint, ReturnSubscriptionArn: true }),
    );
    return `Subscribed: ${out.SubscriptionArn}${grant ? " (and allowed the topic in the queue policy)" : ""}`;
  }, "/sns/topic");
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

