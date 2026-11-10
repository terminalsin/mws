import "server-only";

import { KinesisClient, ListStreamsCommand } from "@aws-sdk/client-kinesis";
import { all, client } from "@mws-dashboard/aws";

export const kinesis = () => client(KinesisClient);

export const ICONS = {
  kinesis: "service/AmazonKinesisDataStreams",
};

export const streamHref = (name: string, extra: Record<string, string> = {}) =>
  `/kinesis/stream?${new URLSearchParams({ name, ...extra })}`;

/** Every stream (ListStreams pages while HasMoreStreams). */
export async function listStreams() {
  const c = await kinesis();
  return all(
    (NextToken) => c.send(new ListStreamsCommand({ NextToken })),
    (r) => r.StreamSummaries,
    (r) => (r.HasMoreStreams ? r.NextToken : undefined),
  );
}

export const STATUS_TONE = (
  s: string | undefined,
): "good" | "warn" | "bad" | "neutral" => {
  const v = (s ?? "").toLowerCase();
  if (["available", "active", "running", "in-use", "ready"].includes(v))
    return "good";
  if (
    [
      "failed",
      "inaccessible-encryption-credentials",
      "incompatible-parameters",
      "storage-full",
      "deleting",
      "error",
      "degraded",
      "create_failed",
      "delete_failed",
    ].includes(v)
  )
    return "bad";
  if (["stopped", "inactive", "disabled", "draining"].includes(v))
    return "neutral";
  return "warn";
};
