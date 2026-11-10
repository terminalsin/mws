"use server";

import { CreateStreamCommand, DeleteStreamCommand, PutRecordCommand, UpdateShardCountCommand } from "@aws-sdk/client-kinesis";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { kinesis } from "../../lib/clients";

export async function createStream(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const StreamName = required(form, "name", "Stream name");
    const onDemand = (text(form, "mode") || "ON_DEMAND") === "ON_DEMAND";
    await (await kinesis()).send(
      new CreateStreamCommand({ StreamName, StreamModeDetails: { StreamMode: onDemand ? "ON_DEMAND" : "PROVISIONED" }, ShardCount: onDemand ? undefined : Number(text(form, "shards") || 1) }),
    );
    redirect(`/kinesis/stream?name=${encodeURIComponent(StreamName)}`);
  }, { fields: { StreamName: "name", ShardCount: "shards", LimitExceededException: "shards" } });
}

export async function deleteStream(name: string) {
  return act(async () => {
    await (await kinesis()).send(new DeleteStreamCommand({ StreamName: name, EnforceConsumerDeletion: true }));
    redirect("/kinesis");
  });
}

export async function putRecord(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await kinesis()).send(
      new PutRecordCommand({ StreamName: name, PartitionKey: text(form, "key") || `${Date.now()}`, Data: new TextEncoder().encode(required(form, "data", "Data")) }),
    );
    return `Sent to ${out.ShardId}`;
  }, { revalidate: ["/kinesis/stream"], fields: { PartitionKey: "key", Data: "data" } });
}

export async function reshard(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const TargetShardCount = Number(required(form, "shards", "Shards"));
    await (await kinesis()).send(new UpdateShardCountCommand({ StreamName: name, TargetShardCount, ScalingType: "UNIFORM_SCALING" }));
    return `Resharding to ${TargetShardCount}`;
  }, { revalidate: ["/kinesis/stream"], fields: { TargetShardCount: "shards", LimitExceededException: "shards" } });
}
