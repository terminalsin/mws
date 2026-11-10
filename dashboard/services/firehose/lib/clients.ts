import "server-only";

import {
  FirehoseClient,
  ListDeliveryStreamsCommand,
} from "@aws-sdk/client-firehose";
import { IAMClient } from "@aws-sdk/client-iam";
import { KinesisClient } from "@aws-sdk/client-kinesis";
import { client } from "@mws-dashboard/aws";

export const firehose = () => client(FirehoseClient);
export const iam = () => client(IAMClient);
export const kinesis = () => client(KinesisClient);

export const ICONS = {
  kinesis: "service/AmazonKinesisDataStreams",
  firehose: "service/AmazonDataFirehose",
};

export const streamHref = (name: string, extra: Record<string, string> = {}) =>
  `/firehose/stream?${new URLSearchParams({ name, ...extra })}`;

/** One page of stream names after `start` (ListDeliveryStreams pages by the
 * last name seen, not by token). */
export async function namesPage(start?: string, limit = 50) {
  const out = await (
    await firehose()
  ).send(
    new ListDeliveryStreamsCommand({
      Limit: limit,
      ExclusiveStartDeliveryStreamName: start || undefined,
    }),
  );
  const names = out.DeliveryStreamNames ?? [];
  return {
    names,
    next:
      out.HasMoreDeliveryStreams && names.length
        ? names[names.length - 1]
        : undefined,
  };
}

/** Every stream name. */
export async function allNames(): Promise<string[]> {
  const names: string[] = [];
  let start: string | undefined;
  do {
    const page = await namesPage(start, 10_000);
    names.push(...page.names);
    start = page.next;
  } while (start && names.length < 10_000);
  return names;
}

export const STATUS_TONE = (
  s: string | undefined,
): "good" | "warn" | "bad" | "neutral" => {
  const v = (s ?? "").toLowerCase();
  if (
    ["available", "active", "running", "in-use", "ready", "enabled"].includes(v)
  )
    return "good";
  if (
    [
      "failed",
      "deleting",
      "error",
      "creating_failed",
      "deleting_failed",
      "enabling_failed",
      "disabling_failed",
      "suspended",
    ].includes(v)
  )
    return "bad";
  if (["stopped", "inactive", "disabled", "draining"].includes(v))
    return "neutral";
  return "warn";
};
