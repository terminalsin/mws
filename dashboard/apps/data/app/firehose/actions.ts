"use server";

import { CreateDeliveryStreamCommand, DeleteDeliveryStreamCommand, PutRecordCommand } from "@aws-sdk/client-firehose";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { firehose } from "../../lib/clients";

export async function createDeliveryStream(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const source = text(form, "source");
    const bucket = required(form, "bucket", "S3 bucket");
    await (await firehose()).send(
      new CreateDeliveryStreamCommand({
        DeliveryStreamName: name,
        DeliveryStreamType: source ? "KinesisStreamAsSource" : "DirectPut",
        KinesisStreamSourceConfiguration: source ? { KinesisStreamARN: source, RoleARN: required(form, "role", "Role") } : undefined,
        ExtendedS3DestinationConfiguration: {
          BucketARN: bucket.startsWith("arn:") ? bucket : `arn:aws:s3:::${bucket}`,
          RoleARN: required(form, "role", "Role"),
          Prefix: text(form, "prefix") || undefined,
          BufferingHints: { IntervalInSeconds: Number(text(form, "interval") || 60), SizeInMBs: 1 },
        },
      }),
    );
    redirect(`/firehose/stream?name=${encodeURIComponent(name)}`);
  });
}

export async function deleteDeliveryStream(name: string) {
  return act(async () => {
    await (await firehose()).send(new DeleteDeliveryStreamCommand({ DeliveryStreamName: name }));
    redirect("/firehose");
  });
}

export async function putFirehoseRecord(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await firehose()).send(new PutRecordCommand({ DeliveryStreamName: name, Record: { Data: new TextEncoder().encode(required(form, "data", "Data") + "\n") } }));
    return `Record ${out.RecordId?.slice(0, 12)}… accepted`;
  }, "/firehose/stream");
}
