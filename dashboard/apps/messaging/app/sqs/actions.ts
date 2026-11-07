"use server";

import {
  CreateQueueCommand,
  DeleteMessageBatchCommand,
  DeleteQueueCommand,
  GetQueueUrlCommand,
  PurgeQueueCommand,
  ReceiveMessageCommand,
  SendMessageCommand,
  SetQueueAttributesCommand,
  StartMessageMoveTaskCommand,
} from "@aws-sdk/client-sqs";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { sqs } from "../../lib/clients";

async function url(name: string) {
  return (await (await sqs()).send(new GetQueueUrlCommand({ QueueName: name }))).QueueUrl!;
}

export async function createQueue(_: ActionResult | null, form: FormData) {
  return act(async () => {
    let name = required(form, "name", "Queue name");
    const fifo = text(form, "fifo") === "on";
    if (fifo && !name.endsWith(".fifo")) name += ".fifo";
    const attributes: Record<string, string> = {};
    const dlq = text(form, "dlq");
    if (dlq) {
      attributes.RedrivePolicy = JSON.stringify({ deadLetterTargetArn: dlq, maxReceiveCount: Number(text(form, "maxReceiveCount") || "5") });
    }
    if (fifo) {
      attributes.FifoQueue = "true";
      if (text(form, "dedup") === "on") attributes.ContentBasedDeduplication = "true";
    }
    await (await sqs()).send(new CreateQueueCommand({ QueueName: name, Attributes: attributes }));
    return `Created queue ${name}`;
  }, "/sqs");
}

export async function sendMessage(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const body = required(form, "body", "Message body");
    const group = text(form, "group");
    const dedup = text(form, "dedup");
    const delay = text(form, "delay");
    const out = await (await sqs()).send(
      new SendMessageCommand({
        QueueUrl: await url(name),
        MessageBody: body,
        ...(group ? { MessageGroupId: group } : {}),
        ...(dedup ? { MessageDeduplicationId: dedup } : {}),
        ...(delay ? { DelaySeconds: Number(delay) } : {}),
      }),
    );
    return `Sent message ${out.MessageId}`;
  }, `/sqs/${encodeURIComponent(name)}`);
}

/** Receive up to 10 messages. Peeking makes them visible again at once;
 * otherwise they are deleted, as a consumer would. */
export async function receiveMessages(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await sqs();
    const queueUrl = await url(name);
    const consume = text(form, "mode") === "delete";
    const out = await client.send(
      new ReceiveMessageCommand({
        QueueUrl: queueUrl,
        MaxNumberOfMessages: 10,
        WaitTimeSeconds: 0,
        MessageSystemAttributeNames: ["All"],
        MessageAttributeNames: ["All"],
        ...(consume ? {} : { VisibilityTimeout: 0 }),
      }),
    );
    const messages = out.Messages ?? [];
    if (consume && messages.length) {
      await client.send(
        new DeleteMessageBatchCommand({
          QueueUrl: queueUrl,
          Entries: messages.map((m, i) => ({ Id: String(i), ReceiptHandle: m.ReceiptHandle! })),
        }),
      );
    }
    if (!messages.length) return { ok: true, message: "No messages available" };
    return {
      ok: true,
      message: `${consume ? "Received and deleted" : "Peeked at"} ${messages.length} message(s)`,
      detail: JSON.stringify(
        messages.map((m) => ({ MessageId: m.MessageId, Body: m.Body, Attributes: m.Attributes, MessageAttributes: m.MessageAttributes })),
        null,
        2,
      ),
    };
  }, `/sqs/${encodeURIComponent(name)}`);
}

export async function purgeQueue(name: string) {
  return act(async () => {
    await (await sqs()).send(new PurgeQueueCommand({ QueueUrl: await url(name) }));
    return "Purged";
  }, `/sqs/${encodeURIComponent(name)}`);
}

export async function deleteQueue(name: string) {
  return act(async () => {
    await (await sqs()).send(new DeleteQueueCommand({ QueueUrl: await url(name) }));
    redirect("/sqs");
  });
}

const ATTRIBUTES = ["VisibilityTimeout", "MessageRetentionPeriod", "DelaySeconds", "MaximumMessageSize", "ReceiveMessageWaitTimeSeconds", "Policy"];

export async function saveAttributes(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Attributes: Record<string, string> = {};
    for (const a of ATTRIBUTES) {
      const v = form.get(a);
      if (typeof v === "string") Attributes[a] = v.trim();
    }
    if (Attributes.Policy) JSON.parse(Attributes.Policy);
    await (await sqs()).send(new SetQueueAttributesCommand({ QueueUrl: await url(name), Attributes }));
    return "Saved";
  }, `/sqs/${encodeURIComponent(name)}`);
}

/** Move a dead-letter queue's messages back to where they came from. */
export async function redrive(dlqArn: string) {
  return act(async () => {
    const out = await (await sqs()).send(new StartMessageMoveTaskCommand({ SourceArn: dlqArn }));
    return `Redrive started (${out.TaskHandle?.slice(0, 8) ?? "task"})`;
  }, "/sqs");
}
