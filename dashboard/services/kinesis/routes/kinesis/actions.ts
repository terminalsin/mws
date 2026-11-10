"use server";

import {
  CreateStreamCommand,
  DecreaseStreamRetentionPeriodCommand,
  DeleteResourcePolicyCommand,
  DeleteStreamCommand,
  DeregisterStreamConsumerCommand,
  DisableEnhancedMonitoringCommand,
  EnableEnhancedMonitoringCommand,
  IncreaseStreamRetentionPeriodCommand,
  MergeShardsCommand,
  PutRecordCommand,
  PutRecordsCommand,
  PutResourcePolicyCommand,
  RegisterStreamConsumerCommand,
  SplitShardCommand,
  StartStreamEncryptionCommand,
  StopStreamEncryptionCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateShardCountCommand,
  UpdateStreamModeCommand,
  type MetricsName,
} from "@aws-sdk/client-kinesis";
import {
  act,
  checkFailures,
  FieldError,
  required,
  text,
  type ActionResult,
} from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { kinesis, streamHref } from "../../lib/clients";

const PAGE = ["/kinesis/stream"];

function tagPairs(form: FormData, field: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text(form, field)
    .split(/[\n,]+/)
    .map((l) => l.trim())
    .filter(Boolean)) {
    const i = line.indexOf("=");
    const k = (i < 0 ? line : line.slice(0, i)).trim();
    if (!k)
      throw new FieldError(field, "Like key=value", "format", {
        format: "tags",
      });
    out[k] = i < 0 ? "" : line.slice(i + 1).trim();
  }
  return out;
}

export async function createStream(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const StreamName = required(form, "name", "Stream name");
      const onDemand = (text(form, "mode") || "ON_DEMAND") === "ON_DEMAND";
      const tags = tagPairs(form, "tags");
      await (
        await kinesis()
      ).send(
        new CreateStreamCommand({
          StreamName,
          StreamModeDetails: {
            StreamMode: onDemand ? "ON_DEMAND" : "PROVISIONED",
          },
          ShardCount: onDemand ? undefined : Number(text(form, "shards") || 1),
          Tags: Object.keys(tags).length ? tags : undefined,
        }),
      );
      redirect(streamHref(StreamName));
    },
    {
      fields: {
        StreamName: "name",
        ShardCount: "shards",
        LimitExceededException: "shards",
        Tags: "tags",
      },
    },
  );
}

export async function deleteStream(name: string) {
  return act(async () => {
    await (
      await kinesis()
    ).send(
      new DeleteStreamCommand({
        StreamName: name,
        EnforceConsumerDeletion: true,
      }),
    );
    redirect("/kinesis");
  });
}

export async function putRecord(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const out = await (
        await kinesis()
      ).send(
        new PutRecordCommand({
          StreamName: name,
          PartitionKey: text(form, "key") || `${Date.now()}`,
          ExplicitHashKey: text(form, "hash") || undefined,
          Data: new TextEncoder().encode(required(form, "data", "Data")),
        }),
      );
      return `Sent to ${out.ShardId}`;
    },
    {
      revalidate: PAGE,
      fields: { PartitionKey: "key", ExplicitHashKey: "hash", Data: "data" },
    },
  );
}

/** PutRecords: one record per line, each with its own random partition key
 * (or the line's index when keys are "by line"). Failed records fail the form. */
export async function putRecords(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const lines = required(form, "data", "Records")
        .split("\n")
        .filter((l) => l.trim());
      if (lines.length > 500)
        throw new FieldError("data", "At most 500 records per call", "range");
      const key = text(form, "key");
      const out = await (
        await kinesis()
      ).send(
        new PutRecordsCommand({
          StreamName: name,
          Records: lines.map((l, i) => ({
            Data: new TextEncoder().encode(l),
            PartitionKey: key || `${Date.now()}-${i}`,
          })),
        }),
      );
      checkFailures(
        (out.Records ?? [])
          .map((r, i) => ({ ...r, i }))
          .filter((r) => r.ErrorCode),
        (r) => `Record ${r.i + 1}: ${r.ErrorCode} ${r.ErrorMessage ?? ""}`,
      );
      return `Sent ${lines.length} records`;
    },
    { revalidate: PAGE, fields: { PartitionKey: "key", Records: "data" } },
  );
}

export async function reshard(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const TargetShardCount = Number(required(form, "shards", "Shards"));
      await (
        await kinesis()
      ).send(
        new UpdateShardCountCommand({
          StreamName: name,
          TargetShardCount,
          ScalingType: "UNIFORM_SCALING",
        }),
      );
      return `Resharding to ${TargetShardCount}`;
    },
    {
      revalidate: PAGE,
      fields: { TargetShardCount: "shards", LimitExceededException: "shards" },
    },
  );
}

/** Split a shard at the middle of its hash key range (or the given key). */
export async function splitShard(
  name: string,
  shard: string,
  middle: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const at = text(form, "hash") || middle;
      await (
        await kinesis()
      ).send(
        new SplitShardCommand({
          StreamName: name,
          ShardToSplit: shard,
          NewStartingHashKey: at,
        }),
      );
      return `Splitting ${shard}`;
    },
    {
      revalidate: PAGE,
      fields: { NewStartingHashKey: "hash", InvalidArgumentException: "hash" },
    },
  );
}

export async function mergeShards(
  name: string,
  shard: string,
  adjacent: string,
) {
  return act(
    async () => {
      await (
        await kinesis()
      ).send(
        new MergeShardsCommand({
          StreamName: name,
          ShardToMerge: shard,
          AdjacentShardToMerge: adjacent,
        }),
      );
      return `Merging ${shard} and ${adjacent}`;
    },
    ...PAGE,
  );
}

export async function setRetention(
  name: string,
  current: number,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const hours = Number(required(form, "hours", "Retention"));
      const c = await kinesis();
      if (hours > current)
        await c.send(
          new IncreaseStreamRetentionPeriodCommand({
            StreamName: name,
            RetentionPeriodHours: hours,
          }),
        );
      else if (hours < current)
        await c.send(
          new DecreaseStreamRetentionPeriodCommand({
            StreamName: name,
            RetentionPeriodHours: hours,
          }),
        );
      return `Retention ${hours} h`;
    },
    {
      revalidate: PAGE,
      fields: {
        RetentionPeriodHours: "hours",
        InvalidArgumentException: "hours",
      },
    },
  );
}

export async function setMode(
  arn: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const mode = required(form, "mode", "Capacity mode") as
        | "ON_DEMAND"
        | "PROVISIONED";
      await (
        await kinesis()
      ).send(
        new UpdateStreamModeCommand({
          StreamARN: arn,
          StreamModeDetails: { StreamMode: mode },
        }),
      );
      return mode === "ON_DEMAND"
        ? "Switching to on-demand"
        : "Switching to provisioned";
    },
    {
      revalidate: PAGE,
      fields: { StreamModeDetails: "mode", LimitExceededException: "mode" },
    },
  );
}

export async function setEncryption(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const key = text(form, "key");
      const c = await kinesis();
      if (text(form, "enabled") === "on")
        await c.send(
          new StartStreamEncryptionCommand({
            StreamName: name,
            EncryptionType: "KMS",
            KeyId: key || "alias/aws/kinesis",
          }),
        );
      else
        await c.send(
          new StopStreamEncryptionCommand({
            StreamName: name,
            EncryptionType: "KMS",
            KeyId: required(form, "current", "Key"),
          }),
        );
      return text(form, "enabled") === "on"
        ? "Encryption on"
        : "Encryption off";
    },
    {
      revalidate: PAGE,
      fields: {
        KeyId: "key",
        KMSNotFoundException: "key",
        KMSAccessDeniedException: "key",
        KMSInvalidStateException: "key",
        KMSDisabledException: "key",
      },
    },
  );
}

const METRICS: MetricsName[] = [
  "IncomingBytes",
  "IncomingRecords",
  "OutgoingBytes",
  "OutgoingRecords",
  "WriteProvisionedThroughputExceeded",
  "ReadProvisionedThroughputExceeded",
  "IteratorAgeMilliseconds",
];

export async function setMonitoring(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const on = form.getAll("metrics").map(String) as MetricsName[];
      const off = METRICS.filter((m) => !on.includes(m));
      const c = await kinesis();
      if (on.length)
        await c.send(
          new EnableEnhancedMonitoringCommand({
            StreamName: name,
            ShardLevelMetrics: on,
          }),
        );
      if (off.length)
        await c.send(
          new DisableEnhancedMonitoringCommand({
            StreamName: name,
            ShardLevelMetrics: off,
          }),
        );
      return on.length
        ? `${on.length} shard-level metrics`
        : "Shard-level metrics off";
    },
    ...PAGE,
  );
}

export async function addTags(
  arn: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const tags = tagPairs(form, "tags");
      if (!Object.keys(tags).length)
        throw new FieldError("tags", "Required", "required");
      await (
        await kinesis()
      ).send(new TagResourceCommand({ ResourceARN: arn, Tags: tags }));
      return "Tagged";
    },
    { revalidate: PAGE, fields: { Tags: "tags" } },
  );
}

export async function removeTag(arn: string, key: string) {
  return act(
    async () => {
      await (
        await kinesis()
      ).send(new UntagResourceCommand({ ResourceARN: arn, TagKeys: [key] }));
      return `Removed ${key}`;
    },
    ...PAGE,
  );
}

export async function savePolicy(
  arn: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const policy = text(form, "policy");
      const c = await kinesis();
      if (policy.trim())
        await c.send(
          new PutResourcePolicyCommand({ ResourceARN: arn, Policy: policy }),
        );
      else await c.send(new DeleteResourcePolicyCommand({ ResourceARN: arn }));
      return policy.trim() ? "Policy saved" : "Policy removed";
    },
    {
      revalidate: PAGE,
      fields: {
        Policy: "policy",
        InvalidArgumentException: "policy",
        MalformedPolicyDocumentException: "policy",
      },
    },
  );
}

export async function registerConsumer(
  arn: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const name = required(form, "name", "Consumer name");
      await (
        await kinesis()
      ).send(
        new RegisterStreamConsumerCommand({
          StreamARN: arn,
          ConsumerName: name,
        }),
      );
      return `Registered ${name}`;
    },
    {
      revalidate: PAGE,
      fields: {
        ConsumerName: "name",
        ResourceInUseException: "name",
        LimitExceededException: "name",
      },
    },
  );
}

export async function deregisterConsumer(consumerArn: string) {
  return act(
    async () => {
      await (
        await kinesis()
      ).send(new DeregisterStreamConsumerCommand({ ConsumerARN: consumerArn }));
      return "Deregistering";
    },
    ...PAGE,
  );
}
