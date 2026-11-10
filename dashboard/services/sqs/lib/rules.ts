// Field rules for the SQS forms. SQS's model leaves its strings and numbers
// unconstrained; the limits below are the ones its docs give (and MWS
// enforces), merged over the model's rules.

import type { Rule } from "@mws-dashboard/ui";
import { CreateQueue, SendMessage } from "@mws-dashboard/ui/model/sqs";

export const QUEUE_NAME: Rule = {
  ...CreateQueue.QueueName,
  pattern: "^[A-Za-z0-9_-]{1,80}$|^[A-Za-z0-9_-]{1,75}\\.fifo$",
  hint: "Letters, digits, - and _",
  generate: "name",
};

const seconds = (min: number, max: number): Rule => ({ type: "integer", min, max, unit: "seconds" });

/** Queue attributes, by attribute name (the form fields use the same names). */
export const ATTRIBUTE_RULES = {
  VisibilityTimeout: seconds(0, 43_200),
  MessageRetentionPeriod: seconds(60, 1_209_600),
  DelaySeconds: seconds(0, 900),
  ReceiveMessageWaitTimeSeconds: seconds(0, 20),
  MaximumMessageSize: { type: "integer", min: 1024, max: 1_048_576, unit: "bytes" },
  Policy: { format: "policy" },
} satisfies Record<string, Rule>;

export const MAX_RECEIVES: Rule = { type: "integer", min: 1, max: 1000 };

// FIFO ids: 1 to 128 alphanumeric or punctuation characters.
const FIFO_ID: Rule = { pattern: "^[!-~]{1,128}$", maxLength: 128, hint: "Letters, digits and punctuation, no spaces" };

export const SEND = {
  MessageBody: SendMessage.MessageBody,
  DelaySeconds: { ...SendMessage.DelaySeconds, ...ATTRIBUTE_RULES.DelaySeconds },
  MessageGroupId: { ...SendMessage.MessageGroupId, ...FIFO_ID, generate: "name" },
  MessageDeduplicationId: { ...SendMessage.MessageDeduplicationId, ...FIFO_ID, generate: "uuid" },
} satisfies Record<string, Rule>;

export const KMS_KEY: Rule = { pattern: "^[a-zA-Z0-9:/_-]+$", hint: "Key ID, alias or ARN", known: ["alias/aws/sqs"] };
export const KMS_REUSE: Rule = seconds(60, 86_400);
export const SOURCE_ARNS: Rule = { format: "list", item: { format: "arn" }, hint: "Queue ARNs, up to 10" };
export const MOVE_RATE: Rule = { type: "integer", min: 1, max: 500, hint: "Messages per second; empty for as fast as possible" };
export const MESSAGE_ATTRIBUTES: Rule = { format: "keyvalue", hint: "Name=value; Name:Number=42 for numbers" };
export const COPIES: Rule = { type: "integer", min: 1, max: 10 };
export const BATCH_SIZE: Rule = { type: "integer", min: 1, max: 10_000 };
