"use server";

import { GetRoleCommand, PutRolePolicyCommand } from "@aws-sdk/client-iam";
import { CreateEventSourceMappingCommand, GetFunctionCommand } from "@aws-sdk/client-lambda";
import {
  CancelMessageMoveTaskCommand,
  ChangeMessageVisibilityCommand,
  CreateQueueCommand,
  DeleteMessageBatchCommand,
  DeleteMessageCommand,
  DeleteQueueCommand,
  GetQueueUrlCommand,
  PurgeQueueCommand,
  ReceiveMessageCommand,
  SendMessageBatchCommand,
  SendMessageCommand,
  SetQueueAttributesCommand,
  StartMessageMoveTaskCommand,
  TagQueueCommand,
  UntagQueueCommand,
  type MessageAttributeValue,
} from "@aws-sdk/client-sqs";
import { act, checkFailures, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { iam, lambda, sqs } from "../../lib/clients";

const page = (name: string) => `/sqs/${encodeURIComponent(name)}`;

async function url(name: string) {
  return (await (await sqs()).send(new GetQueueUrlCommand({ QueueName: name }))).QueueUrl!;
}

const lines = (v: string) =>
  v
    .split(/[\n,\s]+/)
    .map((l) => l.trim())
    .filter(Boolean);

/** The redrive, encryption and FIFO attributes a create or edit form sets. */
function settings(form: FormData, fifo: boolean, editing: boolean): Record<string, string> {
  const a: Record<string, string> = {};
  const dlq = text(form, "dlq");
  if (dlq) a.RedrivePolicy = JSON.stringify({ deadLetterTargetArn: dlq, maxReceiveCount: Number(text(form, "maxReceiveCount") || "5") });
  else if (editing) a.RedrivePolicy = "";
  const allow = text(form, "allow");
  if (allow === "allowAll" || allow === "denyAll") a.RedriveAllowPolicy = JSON.stringify({ redrivePermission: allow });
  else if (allow === "byQueue") {
    const sourceQueueArns = lines(text(form, "allowSources"));
    if (!sourceQueueArns.length) throw new FieldError("allowSources", "Name at least one source queue", "required");
    if (sourceQueueArns.length > 10) throw new FieldError("allowSources", "At most 10 queues", "tooLong");
    a.RedriveAllowPolicy = JSON.stringify({ redrivePermission: "byQueue", sourceQueueArns });
  }
  const encryption = text(form, "encryption");
  if (encryption === "kms") {
    a.KmsMasterKeyId = required(form, "kmsKey", "KMS key");
    const reuse = text(form, "kmsReuse");
    if (reuse) a.KmsDataKeyReusePeriodSeconds = reuse;
    if (editing) a.SqsManagedSseEnabled = "false";
  } else if (encryption === "sqs") {
    a.SqsManagedSseEnabled = "true";
    if (editing) a.KmsMasterKeyId = "";
  } else if (encryption === "none") {
    a.SqsManagedSseEnabled = "false";
    if (editing) a.KmsMasterKeyId = "";
  }
  if (fifo) {
    a.ContentBasedDeduplication = text(form, "dedup") === "on" ? "true" : "false";
    const scope = text(form, "dedupScope");
    const limit = text(form, "throughput");
    if (scope) a.DeduplicationScope = scope;
    if (limit) a.FifoThroughputLimit = limit;
  }
  return a;
}

const TIMINGS = ["VisibilityTimeout", "MessageRetentionPeriod", "DelaySeconds", "MaximumMessageSize", "ReceiveMessageWaitTimeSeconds"];

const QUEUE_FIELDS = {
  QueueName: "name",
  RedrivePolicy: "dlq",
  RedriveAllowPolicy: "allowSources",
  KmsMasterKeyId: "kmsKey",
  KmsDataKeyReusePeriodSeconds: "kmsReuse",
  DeduplicationScope: "dedupScope",
  FifoThroughputLimit: "throughput",
  Policy: "Policy",
  ...Object.fromEntries(TIMINGS.map((t) => [t, t])),
};

/** SQS names the attribute in its InvalidAttributeValue message. */
async function onAttribute<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (e) {
    if (e instanceof Error && /InvalidAttribute/.test(e.name)) {
      const attr = e.message.match(/\b(RedrivePolicy|RedriveAllowPolicy|KmsMasterKeyId|KmsDataKeyReusePeriodSeconds|DeduplicationScope|FifoThroughputLimit|Policy|VisibilityTimeout|MessageRetentionPeriod|DelaySeconds|MaximumMessageSize|ReceiveMessageWaitTimeSeconds)\b/)?.[1];
      const field = attr ? (QUEUE_FIELDS as Record<string, string>)[attr] : undefined;
      if (field) throw new FieldError(field, e.message);
    }
    throw e;
  }
}

export async function createQueue(_: ActionResult | null, form: FormData) {
  return act(async () => {
    let name = required(form, "name", "Queue name");
    // A name ending in .fifo can only be a FIFO queue, so it is one.
    const fifo = text(form, "fifo") === "on" || name.endsWith(".fifo");
    if (fifo && !name.endsWith(".fifo")) name += ".fifo";
    const attributes = settings(form, fifo, false);
    if (fifo) {
      attributes.FifoQueue = "true";
      if (attributes.ContentBasedDeduplication === "false") delete attributes.ContentBasedDeduplication;
    }
    for (const t of TIMINGS) if (text(form, t)) attributes[t] = text(form, t);
    await onAttribute(async () => (await sqs()).send(new CreateQueueCommand({ QueueName: name, Attributes: attributes })));
    return `Created queue ${name}`;
  }, { revalidate: ["/sqs"], fields: QUEUE_FIELDS });
}

/** `Name=value` lines as message attributes; `Name:Number=42` and
 * `Name:Binary=<base64>` pick the data type. */
function messageAttributes(form: FormData): Record<string, MessageAttributeValue> | undefined {
  const raw = text(form, "attributes");
  if (!raw) return undefined;
  const out: Record<string, MessageAttributeValue> = {};
  for (const line of raw.split("\n").map((l) => l.trim()).filter(Boolean)) {
    const eq = line.indexOf("=");
    if (eq < 1) throw new FieldError("attributes", `"${line}" is not Name=value`, "format");
    const [key, type = "String"] = line.slice(0, eq).trim().split(":");
    const value = line.slice(eq + 1).trim();
    const DataType = /^number/i.test(type) ? `Number${type.slice(6)}` : /^binary/i.test(type) ? "Binary" : `String${type.slice(6)}`;
    if (DataType.startsWith("Number") && !Number.isFinite(Number(value))) throw new FieldError("attributes", `${key}: ${value} is not a number`, "format");
    out[key] = DataType === "Binary" ? { DataType, BinaryValue: Buffer.from(value, "base64") } : { DataType, StringValue: value };
  }
  return out;
}

export async function sendMessage(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const body = required(form, "body", "Message body");
    const group = text(form, "group");
    const dedup = text(form, "dedup");
    const delay = text(form, "delay");
    const trace = text(form, "trace");
    const copies = Number(text(form, "copies") || "1");
    const entry = {
      MessageBody: body,
      ...(group ? { MessageGroupId: group } : {}),
      ...(delay ? { DelaySeconds: Number(delay) } : {}),
      MessageAttributes: messageAttributes(form),
      ...(trace ? { MessageSystemAttributes: { AWSTraceHeader: { DataType: "String", StringValue: trace } } } : {}),
    };
    const client = await sqs();
    const QueueUrl = await url(name);
    if (copies > 1) {
      const out = await client.send(
        new SendMessageBatchCommand({
          QueueUrl,
          Entries: Array.from({ length: copies }, (_, i) => ({ Id: String(i), ...entry, ...(dedup ? { MessageDeduplicationId: `${dedup}-${i}` } : {}) })),
        }),
      );
      checkFailures(out.Failed, (f) => `${f.Id}: ${f.Code} ${f.Message ?? ""}`);
      return `Sent ${out.Successful?.length ?? 0} messages`;
    }
    const out = await client.send(new SendMessageCommand({ QueueUrl, ...entry, ...(dedup ? { MessageDeduplicationId: dedup } : {}) }));
    return `Sent message ${out.MessageId}`;
  }, {
    revalidate: [page(name)],
    fields: { MessageBody: "body", MessageGroupId: "group", MessageDeduplicationId: "dedup", DelaySeconds: "delay", MessageAttributes: "attributes", "MessageSystemAttributes.AWSTraceHeader": "trace" },
  });
}

export interface PolledMessage {
  id: string;
  receipt: string;
  body: string;
  receives: number;
  sent?: string;
  firstReceived?: string;
  group?: string;
  attributes: Record<string, string>;
}

export interface PollResult extends ActionResult {
  messages?: PolledMessage[];
  /** What happened to them: released (visible again), kept hidden, or deleted. */
  mode?: "peek" | "poll" | "delete";
}

/** Receive up to 10 messages, as a consumer would: each receive counts
 * toward the redrive policy's maxReceiveCount. "peek" makes them visible
 * again at once; "poll" keeps them hidden for the queue's visibility timeout
 * (as the AWS console's poll does), so they can be deleted one by one;
 * "delete" deletes them all. */
export async function receiveMessages(name: string, _: PollResult | null, form: FormData): Promise<PollResult> {
  const mode = (["peek", "poll", "delete"].includes(text(form, "mode")) ? text(form, "mode") : "peek") as "peek" | "poll" | "delete";
  let messages: PolledMessage[] = [];
  const result = await act(async () => {
    const client = await sqs();
    const QueueUrl = await url(name);
    const out = await client.send(
      new ReceiveMessageCommand({
        QueueUrl,
        MaxNumberOfMessages: 10,
        WaitTimeSeconds: 0,
        MessageSystemAttributeNames: ["All"],
        MessageAttributeNames: ["All"],
        ...(mode === "peek" ? { VisibilityTimeout: 0 } : {}),
      }),
    );
    const received = out.Messages ?? [];
    if (mode === "delete" && received.length) {
      const del = await client.send(new DeleteMessageBatchCommand({ QueueUrl, Entries: received.map((m, i) => ({ Id: String(i), ReceiptHandle: m.ReceiptHandle! })) }));
      checkFailures(del.Failed, (f) => `${f.Id}: ${f.Code}`);
    }
    messages = received.map((m) => ({
      id: m.MessageId!,
      receipt: m.ReceiptHandle!,
      body: m.Body ?? "",
      receives: Number(m.Attributes?.ApproximateReceiveCount ?? 1),
      sent: m.Attributes?.SentTimestamp,
      firstReceived: m.Attributes?.ApproximateFirstReceiveTimestamp,
      group: m.Attributes?.MessageGroupId,
      attributes: Object.fromEntries(Object.entries(m.MessageAttributes ?? {}).map(([k, v]) => [k, v.StringValue ?? `(${v.DataType})`])),
    }));
    if (!received.length) return "No messages available";
    const verb = mode === "delete" ? "Received and deleted" : mode === "peek" ? "Received and released" : "Received";
    return `${verb} ${received.length} message(s)`;
  }, page(name));
  return { ...result, messages, mode };
}

export async function deleteMessage(name: string, receipt: string) {
  return act(async () => {
    await (await sqs()).send(new DeleteMessageCommand({ QueueUrl: await url(name), ReceiptHandle: receipt }));
    return "Message deleted";
  }, page(name));
}

/** Make a received message visible again now. */
export async function releaseMessage(name: string, receipt: string) {
  return act(async () => {
    await (await sqs()).send(new ChangeMessageVisibilityCommand({ QueueUrl: await url(name), ReceiptHandle: receipt, VisibilityTimeout: 0 }));
    return "Returned to the queue";
  }, page(name));
}

export async function purgeQueue(name: string) {
  return act(async () => {
    await (await sqs()).send(new PurgeQueueCommand({ QueueUrl: await url(name) }));
    return "Purged";
  }, page(name));
}

export async function deleteQueue(name: string) {
  return act(async () => {
    await (await sqs()).send(new DeleteQueueCommand({ QueueUrl: await url(name) }));
    redirect("/sqs");
  });
}

export async function saveAttributes(name: string, fifo: boolean, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Attributes: Record<string, string> = settings(form, fifo, true);
    for (const a of [...TIMINGS, "Policy"]) {
      const v = form.get(a);
      // An emptied number keeps its current value; an emptied policy removes it.
      if (typeof v === "string" && (v.trim() || a === "Policy")) Attributes[a] = v.trim();
    }
    if (Attributes.Policy) {
      try {
        JSON.parse(Attributes.Policy);
      } catch (e) {
        throw new FieldError("Policy", (e as Error).message, "format");
      }
    }
    await onAttribute(async () => (await sqs()).send(new SetQueueAttributesCommand({ QueueUrl: await url(name), Attributes })));
    return "Saved";
  }, { revalidate: [page(name), "/sqs"], fields: QUEUE_FIELDS });
}

/** Move a dead-letter queue's messages back to where they came from, or to
 * another queue. */
export async function redrive(name: string, dlqArn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const destination = text(form, "destination");
    const rate = text(form, "rate");
    const out = await (await sqs()).send(
      new StartMessageMoveTaskCommand({ SourceArn: dlqArn, ...(destination ? { DestinationArn: destination } : {}), ...(rate ? { MaxNumberOfMessagesPerSecond: Number(rate) } : {}) }),
    );
    return `Redrive started (${out.TaskHandle?.slice(0, 8) ?? "task"})`;
  }, { revalidate: [page(name), "/sqs"], fields: { DestinationArn: "destination", MaxNumberOfMessagesPerSecond: "rate" } });
}

export async function cancelRedrive(name: string, handle: string) {
  return act(async () => {
    const out = await (await sqs()).send(new CancelMessageMoveTaskCommand({ TaskHandle: handle }));
    return `Cancelled after ${out.ApproximateNumberOfMessagesMoved ?? 0} moved`;
  }, page(name));
}

export async function saveTags(name: string, current: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const tags = Object.fromEntries(
      text(form, "tags")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => {
          const [k, ...v] = l.split("=");
          return [k.trim(), v.join("=").trim()];
        }),
    );
    const client = await sqs();
    const QueueUrl = await url(name);
    const gone = current.filter((k) => !(k in tags));
    if (gone.length) await client.send(new UntagQueueCommand({ QueueUrl, TagKeys: gone }));
    if (Object.keys(tags).length) await client.send(new TagQueueCommand({ QueueUrl, Tags: tags }));
    return "Saved";
  }, { revalidate: [page(name)], fields: { Tags: "tags" } });
}

/** "Configure Lambda function trigger", as the SQS console offers it. */
export async function addLambdaTrigger(name: string, queueArn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const fn = required(form, "function", "Function");
    const client = await lambda();
    if (text(form, "grant") === "on") {
      const role = (await client.send(new GetFunctionCommand({ FunctionName: fn }))).Configuration?.Role?.split("/").pop();
      if (role) {
        const roles = await iam();
        await roles.send(new GetRoleCommand({ RoleName: role }));
        await roles.send(
          new PutRolePolicyCommand({
            RoleName: role,
            PolicyName: `console-${name}`.replace(/[^\w+=,.@-]/g, "-").slice(0, 128),
            PolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"], Resource: queueArn }] }),
          }),
        );
      }
    }
    const batch = text(form, "batch");
    await client
      .send(new CreateEventSourceMappingCommand({ FunctionName: fn, EventSourceArn: queueArn, ...(batch ? { BatchSize: Number(batch) } : {}) }))
      .catch((e) => {
        if (e instanceof Error && /role|visibility timeout/i.test(e.message)) throw new FieldError("function", e.message);
        throw e;
      });
    return "Trigger added";
  }, { revalidate: [page(name)], fields: { FunctionName: "function", BatchSize: "batch", ResourceNotFoundException: "function", ResourceConflictException: "function" } });
}
