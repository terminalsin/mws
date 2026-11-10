import { DescribeDeliveryStreamCommand, ListDeliveryStreamsCommand } from "@aws-sdk/client-firehose";
import { ago, load } from "@mws-dashboard/aws";
import { bucketOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { ArrowRight } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, firehose } from "../../lib/clients";
import { rolesTrusting } from "../../lib/network";
import { createDeliveryStream } from "./actions";
import { destinationOf } from "../../lib/firehose";

export const metadata: Metadata = { title: "Firehose" };

export default async function DeliveryStreams() {
  const [streams, roles, buckets] = await Promise.all([
    load(async () => {
      const client = await firehose();
      const names = (await client.send(new ListDeliveryStreamsCommand({ Limit: 100 }))).DeliveryStreamNames ?? [];
      return Promise.all(names.map((n) => client.send(new DescribeDeliveryStreamCommand({ DeliveryStreamName: n })).then((r) => r.DeliveryStreamDescription!)));
    }),
    load(() => rolesTrusting("firehose.amazonaws.com")),
    bucketOptions(),
  ]);
  const create = (
    <Sheet title="Create Firehose stream" label="Create Firehose stream" testId="create-delivery-stream">
      <ActionForm action={createDeliveryStream} submit="Create" testId="create-delivery-stream">
        <Field label="Name">
          <input name="name" required pattern="[a-zA-Z0-9_.\-]+" autoFocus />
        </Field>
        <AutoPick name="bucket" label="Destination bucket" creates="firehose-<account>-<region>" options={buckets} testId="destination-bucket" />
        <Field label="Prefix">
          <input name="prefix" placeholder="events/" />
        </Field>
        <AutoPick name="role" label="Role" creates="KinesisFirehoseServiceRole-<stream>" options={roles.ok ? roles.value.map((r) => ({ value: r.Arn!, label: r.RoleName! })) : []} testId="firehose-role" />
        <Field label="Source Kinesis stream ARN">
          <input name="source" placeholder="Direct PUT" />
        </Field>
        <Field label="Buffer interval (s)">
          <input name="interval" type="number" min={0} max={900} defaultValue={60} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Firehose streams" actions={create}>
      {streams.ok ? (
        <List
          label="Firehose streams"
          empty={<Empty icon={ICONS.firehose} action={create} />}
          rows={streams.value.map((s) => {
            const d = destinationOf(s);
            return {
              key: s.DeliveryStreamARN!,
              icon: <AwsIcon icon={ICONS.firehose} size={24} />,
              title: s.DeliveryStreamName,
              subtitle: (
                <>
                  {s.DeliveryStreamType === "KinesisStreamAsSource" ? s.Source?.KinesisStreamSourceDescription?.KinesisStreamARN?.split("/").pop() : "Direct PUT"} <ArrowRight size={11} aria-hidden /> {d.target}
                </>
              ),
              href: `/firehose/stream?name=${encodeURIComponent(s.DeliveryStreamName!)}`,
              meta: (
                <>
                  <Pill>{d.kind}</Pill>
                  <Status tone={STATUS_TONE(s.DeliveryStreamStatus)}>{s.DeliveryStreamStatus?.toLowerCase()}</Status>
                  <span>{ago(s.CreateTimestamp)}</span>
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={streams.error} />
      )}
    </Page>
  );
}
