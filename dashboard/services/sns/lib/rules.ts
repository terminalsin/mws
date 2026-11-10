// Field rules for the SNS forms. SNS's model leaves most members
// unconstrained; the limits below are the ones its documentation states and
// MWS enforces (crates/services/mws-sns: names.rs, publish.rs,
// subscriptions.rs).

import type { Rule } from "@mws-dashboard/ui";
import { CreateTopic, Publish, Subscribe } from "@mws-dashboard/ui/model/sns";

export const TOPIC_NAME: Rule = {
  ...CreateTopic.Name,
  maxLength: 256,
  pattern: "^[A-Za-z0-9_-]{1,256}$|^[A-Za-z0-9_-]{1,251}\\.fifo$",
  hint: "Letters, digits, - and _",
  generate: "name",
};

/** Printable ASCII, not starting with a space, under 100 characters. */
export const SUBJECT: Rule = { ...Publish.Subject, maxLength: 99, pattern: "^[!-~][ -~]*$", hint: "ASCII, no leading space" };

export const MESSAGE: Rule = { ...Publish.Message, maxLength: 262144 };

/** MessageGroupId and MessageDeduplicationId: 1-128 letters, digits and punctuation. */
const FIFO_ID: Rule = { required: true, maxLength: 128, pattern: "^[!-~]+$", hint: "Letters, digits and punctuation" };
export const GROUP_ID: Rule = { ...Publish.MessageGroupId, ...FIFO_ID, generate: "name" };
export const DEDUP_ID: Rule = { ...Publish.MessageDeduplicationId, ...FIFO_ID, generate: "uuid" };

export const PROTOCOLS = ["sqs", "lambda", "email", "email-json", "sms", "http", "https", "firehose", "application"] as const;
export type Protocol = (typeof PROTOCOLS)[number];

/** Where a subscription's endpoint and role ARNs live. */
export interface Scope {
  partition: string;
  region: string;
  account: string;
}

export function scopeOf(topicArn: string): Scope {
  const [, partition = "aws", , region = "", account = ""] = topicArn.split(":");
  return { partition, region, account };
}

const arnRule = (s: Scope, service: string, resource: string, hint: string): Rule => ({
  format: "arn",
  arn: `arn:${s.partition}:${service}:${s.region}:${s.account}:${resource}{}`,
  pattern: `^arn:[\\w-]+:${service}:[\\w-]+:\\d{12}:${resource.replace(/\//g, "\\/")}.+$`,
  hint,
});

/** The endpoint's rule for a protocol, as SNS checks it on Subscribe. */
export function endpointRule(protocol: string, s: Scope, fifoTopic: boolean): Rule {
  const base: Rule = { ...Subscribe.Endpoint, required: true };
  switch (protocol) {
    case "sqs":
      // A standard topic cannot deliver to a FIFO queue.
      return { ...base, ...arnRule(s, "sqs", "", "Queue ARN"), ...(fifoTopic ? {} : { pattern: "^arn:[\\w-]+:sqs:[\\w-]+:\\d{12}:[\\w-]+$" }) };
    case "lambda":
      return { ...base, ...arnRule(s, "lambda", "function:", "Function ARN") };
    case "firehose":
      return { ...base, ...arnRule(s, "firehose", "deliverystream/", "Delivery stream ARN") };
    case "application":
      return { ...base, ...arnRule(s, "sns", "endpoint/", "Platform endpoint ARN") };
    case "email":
    case "email-json":
      return { ...base, format: "email" };
    case "sms":
      return { ...base, format: "phone" };
    case "http":
      return { ...base, format: "url", pattern: "^http://\\S+$", hint: "http:// URL" };
    case "https":
      return { ...base, format: "url", pattern: "^https://\\S+$", hint: "https:// URL" };
    default:
      return base;
  }
}

export const roleRule = (s: Scope): Rule => ({
  required: true,
  format: "arn",
  arn: `arn:${s.partition}:iam::${s.account}:role/{}`,
  pattern: "^arn:[\\w-]+:iam::\\d{12}:role/.+$",
  hint: "Role SNS assumes to write to the stream",
});

export const DISPLAY_NAME: Rule = { maxLength: 100, hint: "Shown as the sender of SMS and email" };
export const FILTER_POLICY: Rule = { format: "json", hint: '{"type": ["order"]}' };
export const JSON_POLICY: Rule = { format: "json" };
export const ACCESS_POLICY: Rule = { format: "policy" };
export const MESSAGE_ATTRIBUTES: Rule = { format: "keyvalue", hint: "Name=value; Name:Number=42 for numbers" };
export const KMS_KEY: Rule = { pattern: "^[a-zA-Z0-9:/_-]+$", hint: "Key ID, alias or ARN", known: ["alias/aws/sns"] };
export const SAMPLE_RATE: Rule = { type: "integer", min: 0, max: 100, hint: "Percent of successful deliveries logged" };
export const RETENTION_DAYS: Rule = { type: "integer", min: 1, max: 365, hint: "Days" };
export const DLQ_ARN: Rule = { format: "arn", pattern: "^arn:[\\w-]+:sqs:[\\w-]+:\\d{12}:[\\w.-]+$", hint: "An SQS queue ARN" };
