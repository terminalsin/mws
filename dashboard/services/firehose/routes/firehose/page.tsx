import { DescribeDeliveryStreamCommand, ListDeliveryStreamsCommand } from "@aws-sdk/client-firehose";
import { ListStreamsCommand } from "@aws-sdk/client-kinesis";
import { ago, frameInfo, load } from "@mws-dashboard/aws";
import { bucketOptions } from "@mws-dashboard/aws/auto";
import { ActionForm, AutoPick, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { ArrowRight } from "lucide-react";
import { CreateDeliveryStream as Rules } from "@mws-dashboard/ui/model/firehose";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, firehose, kinesis } from "../../lib/clients";
import { rolesTrusting } from "../../lib/network";
import { createDeliveryStream } from "./actions";
import { destinationOf } from "../../lib/firehose";

export const metadata: Metadata = { title: "Firehose" };

const S3 = Rules.ExtendedS3DestinationConfiguration.fields!;
const NAME = { ...Rules.DeliveryStreamName, hint: "Letters, digits, . - and _" };
const SOURCE = { ...Rules.KinesisStreamSourceConfiguration.fields!.KinesisStreamARN, required: false };

export default async function DeliveryStreams() {
  const [streams, roles, buckets, sources, info] = await Promise.all([
    load(async () => {
      const client = await firehose();
      const names = (await client.send(new ListDeliveryStreamsCommand({ Limit: 100 }))).DeliveryStreamNames ?? [];
      return Promise.all(names.map((n) => client.send(new DescribeDeliveryStreamCommand({ DeliveryStreamName: n })).then((r) => r.DeliveryStreamDescription!)));
    }),
    load(() => rolesTrusting("firehose.amazonaws.com")),
    bucketOptions(),
    load(async () => (await (await kinesis()).send(new ListStreamsCommand({ Limit: 100 }))).StreamSummaries ?? []),
    frameInfo(),
  ]);
  const names = streams.ok ? streams.value.map((s) => s.DeliveryStreamName!) : [];
  const create = (
    <Sheet title="Create Firehose stream" label="Create Firehose stream" testId="create-delivery-stream">
      <ActionForm action={createDeliveryStream} submit="Create" testId="create-delivery-stream">
        <Field label="Name" rule={NAME} taken={names} generate="name" unique>
          <input name="name" required autoFocus />
        </Field>
        <AutoPick name="bucket" label="Destination bucket" creates="firehose-<account>-<region>" options={buckets} testId="destination-bucket" />
        <Field label="Prefix" rule={S3.Prefix}>
          <input name="prefix" placeholder="events/" />
        </Field>
        <AutoPick name="role" label="Role" creates="KinesisFirehoseServiceRole-<stream>" options={roles.ok ? roles.value.map((r) => ({ value: r.Arn!, label: r.RoleName! })) : []} testId="firehose-role" />
        <Field
          label="Source Kinesis stream ARN"
          rule={SOURCE}
          format="arn"
          known={sources.ok ? sources.value.map((k) => k.StreamARN!) : []}
          arn={info.account ? `arn:aws:kinesis:${info.region}:${info.account}:stream/{}` : undefined}
        >
          <input name="source" placeholder="Direct PUT" />
        </Field>
        <Field label="Buffer interval (s)" rule={S3.BufferingHints.fields!.IntervalInSeconds}>
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
