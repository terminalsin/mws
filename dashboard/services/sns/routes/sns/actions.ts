"use server";

import { AddPermissionCommand, GetPolicyCommand } from "@aws-sdk/client-lambda";
import {
  ConfirmSubscriptionCommand,
  CreateTopicCommand,
  DeleteTopicCommand,
  GetSubscriptionAttributesCommand,
  GetTopicAttributesCommand,
  PublishCommand,
  SetSubscriptionAttributesCommand,
  SetTopicAttributesCommand,
  SubscribeCommand,
  TagResourceCommand,
  UnsubscribeCommand,
  UntagResourceCommand,
  type MessageAttributeValue,
} from "@aws-sdk/client-sns";
import { GetQueueAttributesCommand, GetQueueUrlCommand, SetQueueAttributesCommand } from "@aws-sdk/client-sqs";
import { act, FieldError, mws, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { lambda, sns, sqs } from "../../lib/clients";

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
  [/^(FilterPolicy|Filter policy)/i, "filter", "Not a valid filter policy"],
  [/^FilterPolicyScope/, "filterScope", "MessageBody or MessageAttributes"],
  [/raw message delivery|^RawMessageDelivery/i, "raw", "Not available for this protocol"],
  [/^RedrivePolicy/, "dlq", "An SQS queue ARN"],
  [/^DeliveryPolicy/, "deliveryPolicy", "Not valid JSON"],
  [/^DisplayName/, "displayName", "At most 100 characters"],
  [/^Policy Error/, "policy", "Not a valid policy"],
  [/^ArchivePolicy/, "archive", "1 to 365 days"],
  [/^TracingConfig/, "tracing", "PassThrough or Active"],
  [/^Message Structure|MessageStructure/i, "message", "With JSON structure the message is a JSON object with a default key"],
  [/^Message attributes|MessageAttributes/i, "attributes", "Name=value lines"],
  [/FeedbackRoleArn$/, "successRole", "A role ARN"],
  [/FeedbackSampleRate$/, "sampleRate", "0 to 100"],
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
    const fifo = text(form, "fifo") === "on" || name.endsWith(".fifo");
    if (fifo && !name.endsWith(".fifo")) name += ".fifo";
    const Attributes: Record<string, string> = {};
    if (fifo) {
      Attributes.FifoTopic = "true";
      if (text(form, "dedup") === "on") Attributes.ContentBasedDeduplication = "true";
    }
    if (text(form, "displayName")) Attributes.DisplayName = text(form, "displayName");
    const client = await sns();
    const out = await onFields(() => client.send(new CreateTopicCommand({ Name: name, Attributes })));
    return `Created ${out.TopicArn}`;
  }, { revalidate: ["/sns"], fields: { Name: "name", DisplayName: "displayName" } });
}

export async function publish(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const subject = text(form, "subject");
    const group = text(form, "group");
    const dedup = text(form, "dedup");
    const message = required(form, "message", "Message");
    const structure = text(form, "structure") === "json";
    if (structure) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(message);
      } catch {
        throw new FieldError("message", "Invalid JSON", "format");
      }
      if (!parsed || typeof parsed !== "object" || !("default" in parsed)) throw new FieldError("message", 'Needs a "default" key', "format");
    }
    const client = await sns();
    const out = await onFields(() =>
      client.send(
        new PublishCommand({
          TopicArn: arn,
          Message: message,
          ...(structure ? { MessageStructure: "json" } : {}),
          MessageAttributes: messageAttributes(form),
          ...(subject ? { Subject: subject } : {}),
          ...(group ? { MessageGroupId: group } : {}),
          ...(dedup ? { MessageDeduplicationId: dedup } : {}),
        }),
      ),
    );
    return `Published ${out.MessageId}`;
  }, { revalidate: ["/sns/topic"], fields: { Subject: "subject", MessageGroupId: "group", MessageDeduplicationId: "dedup", MessageAttributes: "attributes", MessageStructure: "structure" } });
}

export async function subscribe(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = required(form, "protocol", "Protocol");
    const endpoint = required(form, "endpoint", "Endpoint");
    const role = protocol === "firehose" ? required(form, "role", "Subscription role") : "";
    const grant = (protocol === "sqs" || protocol === "lambda") && text(form, "grant") === "on";
    if (grant && protocol === "sqs") await allowTopicOnQueue(arn, endpoint);
    if (grant && protocol === "lambda") await allowTopicOnFunction(arn, endpoint);
    const Attributes = subscriptionAttributes(form, protocol);
    if (role) Attributes.SubscriptionRoleArn = role;
    const client = await sns();
    const out = await onFields(() =>
      client.send(
        new SubscribeCommand({
          TopicArn: arn,
          Protocol: protocol,
          Endpoint: endpoint,
          ReturnSubscriptionArn: true,
          ...(Object.keys(Attributes).length ? { Attributes } : {}),
        }),
      ),
    );
    const where = protocol === "sqs" ? "queue policy" : "function policy";
    return `Subscribed: ${out.SubscriptionArn}${grant ? ` (and allowed the topic in the ${where})` : ""}`;
  }, { revalidate: ["/sns/topic", "/sns/subscriptions"], fields: { Endpoint: "endpoint", Protocol: "protocol", SubscriptionRoleArn: "role", FilterPolicy: "filter", RedrivePolicy: "dlq" } });
}

export async function unsubscribe(subscriptionArn: string) {
  return act(async () => {
    await (await sns()).send(new UnsubscribeCommand({ SubscriptionArn: subscriptionArn }));
    return "Unsubscribed";
  }, "/sns/topic", "/sns/subscriptions", "/sns/subscription");
}

export async function deleteTopic(arn: string) {
  return act(async () => {
    await (await sns()).send(new DeleteTopicCommand({ TopicArn: arn }));
    redirect("/sns");
  });
}

export async function clearOutbox(kind: "email-messages" | "sms-messages" | "platform-endpoint-messages") {
  return act(async () => {
    await mws(`/_aws/sns/${kind}`, { method: "DELETE" });
    return "Cleared";
  }, "/sns");
}


/** Let the topic invoke the function, as the AWS console does when it
 * subscribes one: SNS invokes Lambda only when the function policy allows
 * sns.amazonaws.com for this topic. */
async function allowTopicOnFunction(topicArn: string, functionArn: string) {
  const client = await lambda();
  const StatementId = `sns-${topicArn.split(":").slice(3).join("-")}`.replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 100);
  const existing = await client
    .send(new GetPolicyCommand({ FunctionName: functionArn }))
    .then((r) => ((JSON.parse(r.Policy ?? "{}").Statement ?? []) as { Sid?: string }[]).map((s) => s.Sid), (e: unknown) => {
      if (e instanceof Error && e.name === "ResourceNotFoundException" && /Function not found/i.test(e.message)) throw new FieldError("endpoint", "No such function", "missing");
      return [] as (string | undefined)[];
    });
  if (existing.includes(StatementId)) return;
  await client.send(new AddPermissionCommand({ FunctionName: functionArn, StatementId, Action: "lambda:InvokeFunction", Principal: "sns.amazonaws.com", SourceArn: topicArn }));
}

/** `Name=value` lines as message attributes; `Name:Number=42`,
 * `Name:String.Array=["a","b"]` and `Name:Binary=<base64>` pick the type. */
function messageAttributes(form: FormData): Record<string, MessageAttributeValue> | undefined {
  const raw = text(form, "attributes");
  if (!raw) return undefined;
  const out: Record<string, MessageAttributeValue> = {};
  for (const line of raw.split("\n").map((l) => l.trim()).filter(Boolean)) {
    const eq = line.indexOf("=");
    if (eq < 1) throw new FieldError("attributes", `"${line}" is not Name=value`, "format");
    const [key, type = "String"] = line.slice(0, eq).trim().split(":");
    const value = line.slice(eq + 1).trim();
    const DataType = /^number/i.test(type) ? "Number" : /^binary/i.test(type) ? "Binary" : /array/i.test(type) ? "String.Array" : "String";
    if (DataType === "Number" && !Number.isFinite(Number(value))) throw new FieldError("attributes", `${key}: ${value} is not a number`, "format");
    out[key] = DataType === "Binary" ? { DataType, BinaryValue: Buffer.from(value, "base64") } : { DataType, StringValue: value };
  }
  return out;
}

/** Filter policy, raw delivery and dead-letter queue from a subscribe or
 * edit form, as subscription attributes. */
function subscriptionAttributes(form: FormData, protocol: string): Record<string, string> {
  const a: Record<string, string> = {};
  const filter = text(form, "filter");
  if (filter) {
    try {
      JSON.parse(filter);
    } catch {
      throw new FieldError("filter", "Invalid JSON", "format");
    }
    a.FilterPolicy = filter;
    a.FilterPolicyScope = text(form, "filterScope") || "MessageAttributes";
  }
  if (text(form, "raw") === "on" && ["sqs", "http", "https", "firehose"].includes(protocol)) a.RawMessageDelivery = "true";
  const dlq = text(form, "dlq");
  if (dlq) a.RedrivePolicy = JSON.stringify({ deadLetterTargetArn: dlq });
  return a;
}

/** Confirm a pending subscription with the token MWS kept for it (what the
 * link in the confirmation message carries). */
export async function confirmPending(topicArn: string, protocol: string, endpoint: string) {
  return act(async () => {
    const client = await sns();
    // Subscribing again is idempotent and names the pending subscription.
    const { SubscriptionArn } = await client.send(new SubscribeCommand({ TopicArn: topicArn, Protocol: protocol, Endpoint: endpoint, ReturnSubscriptionArn: true }));
    const { subscriptionToken } = await mws<{ subscriptionToken: string }>(`/_aws/sns/subscription-tokens/${encodeURIComponent(SubscriptionArn!)}`);
    await client.send(new ConfirmSubscriptionCommand({ TopicArn: topicArn, Token: subscriptionToken }));
    return "Subscription confirmed";
  }, "/sns/topic", "/sns/subscriptions", "/sns");
}

export async function saveSubscription(arn: string, protocol: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await sns();
    const current = (await client.send(new GetSubscriptionAttributesCommand({ SubscriptionArn: arn }))).Attributes ?? {};
    const filter = text(form, "filter");
    if (filter) {
      try {
        JSON.parse(filter);
      } catch {
        throw new FieldError("filter", "Invalid JSON", "format");
      }
    }
    const delivery = text(form, "deliveryPolicy");
    if (delivery) {
      try {
        JSON.parse(delivery);
      } catch {
        throw new FieldError("deliveryPolicy", "Invalid JSON", "format");
      }
    }
    const dlq = text(form, "dlq");
    const wanted: [string, string][] = [
      ["FilterPolicyScope", filter ? text(form, "filterScope") || "MessageAttributes" : (current.FilterPolicyScope ?? "")],
      ["FilterPolicy", filter],
      ["RedrivePolicy", dlq ? JSON.stringify({ deadLetterTargetArn: dlq }) : ""],
      ["DeliveryPolicy", delivery],
    ];
    if (["sqs", "http", "https", "firehose"].includes(protocol)) wanted.push(["RawMessageDelivery", text(form, "raw") === "on" ? "true" : "false"]);
    const same = (k: string, v: string) => {
      const c = current[k] ?? "";
      if (k === "RawMessageDelivery") return (c || "false") === v;
      try {
        return JSON.stringify(JSON.parse(c)) === JSON.stringify(JSON.parse(v));
      } catch {
        return c === v;
      }
    };
    let changed = 0;
    for (const [AttributeName, AttributeValue] of wanted) {
      if (same(AttributeName, AttributeValue)) continue;
      if (AttributeName === "FilterPolicyScope" && !AttributeValue) continue;
      await onFields(() => client.send(new SetSubscriptionAttributesCommand({ SubscriptionArn: arn, AttributeName, AttributeValue })));
      changed++;
    }
    return changed ? "Saved" : "Nothing changed";
  }, { revalidate: ["/sns/subscription", "/sns/topic"], fields: { FilterPolicy: "filter", RedrivePolicy: "dlq", DeliveryPolicy: "deliveryPolicy" } });
}

/** Set the topic attributes the form changed, one SetTopicAttributes each. */
export async function saveTopic(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await sns();
    const current = (await client.send(new GetTopicAttributesCommand({ TopicArn: arn }))).Attributes ?? {};
    const fifo = current.FifoTopic === "true";
    for (const [field, label] of [["policy", "policy"], ["deliveryPolicy", "JSON"]]) {
      const v = text(form, field);
      if (v) {
        try {
          JSON.parse(v);
        } catch {
          throw new FieldError(field, `Invalid ${label}`, "format");
        }
      }
    }
    const days = text(form, "archive");
    const wanted: [string, string][] = [
      ["DisplayName", text(form, "displayName")],
      ["KmsMasterKeyId", text(form, "encryption") === "on" ? text(form, "kmsKey") || "alias/aws/sns" : ""],
      ["TracingConfig", text(form, "tracing") === "on" ? "Active" : "PassThrough"],
      ["Policy", text(form, "policy")],
      ["DeliveryPolicy", text(form, "deliveryPolicy")],
    ];
    if (fifo) {
      wanted.push(["ContentBasedDeduplication", text(form, "dedup") === "on" ? "true" : "false"]);
      wanted.push(["ArchivePolicy", days ? JSON.stringify({ MessageRetentionPeriod: days }) : ""]);
    }
    const same = (k: string, v: string) => {
      const c = current[k] ?? (k === "TracingConfig" ? "PassThrough" : "");
      try {
        return JSON.stringify(JSON.parse(c)) === JSON.stringify(JSON.parse(v));
      } catch {
        return c === v;
      }
    };
    let changed = 0;
    for (const [AttributeName, AttributeValue] of wanted) {
      if (same(AttributeName, AttributeValue)) continue;
      // An emptied policy keeps the topic's (SNS needs one); an emptied delivery policy resets it.
      if (AttributeName === "Policy" && !AttributeValue) continue;
      if (AttributeName === "DeliveryPolicy" && !AttributeValue && !current.DeliveryPolicy) continue;
      await onFields(() => client.send(new SetTopicAttributesCommand({ TopicArn: arn, AttributeName, AttributeValue })));
      changed++;
    }
    return changed ? "Saved" : "Nothing changed";
  }, { revalidate: ["/sns/topic", "/sns"], fields: { DisplayName: "displayName", KmsMasterKeyId: "kmsKey", Policy: "policy", DeliveryPolicy: "deliveryPolicy" } });
}

/** Delivery status logging for one protocol: the roles SNS writes
 * CloudWatch Logs as, and the share of successes it logs. */
export async function saveLogging(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const protocol = required(form, "protocol", "Protocol");
    const client = await sns();
    const set = (suffix: string, value: string) =>
      onFields(() => client.send(new SetTopicAttributesCommand({ TopicArn: arn, AttributeName: `${protocol}${suffix}`, AttributeValue: value })));
    await set("SuccessFeedbackRoleArn", text(form, "successRole"));
    await set("FailureFeedbackRoleArn", text(form, "failureRole"));
    await set("SuccessFeedbackSampleRate", text(form, "sampleRate") || "0");
    return "Saved";
  }, { revalidate: ["/sns/topic"] });
}

export async function saveTopicTags(arn: string, current: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const tags = text(form, "tags")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [k, ...v] = l.split("=");
        return { Key: k.trim(), Value: v.join("=").trim() };
      });
    const client = await sns();
    const gone = current.filter((k) => !tags.some((t) => t.Key === k));
    if (gone.length) await client.send(new UntagResourceCommand({ ResourceArn: arn, TagKeys: gone }));
    if (tags.length) await client.send(new TagResourceCommand({ ResourceArn: arn, Tags: tags }));
    return "Saved";
  }, { revalidate: ["/sns/topic"], fields: { Tags: "tags" } });
}
