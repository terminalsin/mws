import { DescribeDeliveryStreamCommand } from "@aws-sdk/client-firehose";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Page, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { ArrowRight, Clock, Lock, Send, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, firehose } from "../../../lib/clients";
import { destinationOf } from "../../../lib/firehose";
import { deleteDeliveryStream, putFirehoseRecord } from "../actions";

export const metadata: Metadata = { title: "Firehose stream" };

type Props = { searchParams: Promise<{ name?: string }> };

export default async function DeliveryStream({ searchParams }: Props) {
  const { name = "" } = await searchParams;
  const back = { href: "/firehose", label: "Firehose streams" };
  const data = await load(async () => (await (await firehose()).send(new DescribeDeliveryStreamCommand({ DeliveryStreamName: name }))).DeliveryStreamDescription!);
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.firehose} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const s = data.value;
  const d = destinationOf(s);
  const s3 = s.Destinations?.[0]?.ExtendedS3DestinationDescription;
  const source = s.Source?.KinesisStreamSourceDescription?.KinesisStreamARN;
  return (
    <Page
      title={name}
      icon={ICONS.firehose}
      back={back}
      subtitle={s.DeliveryStreamARN}
      actions={
        <>
          {!source && (
            <Sheet title="Test with demo data" label="Put record" icon={<Send size={16} />} testId="put-firehose-record">
              <ActionForm action={putFirehoseRecord.bind(null, name)} submit="Put record" testId="put-firehose-record">
                <textarea name="data" rows={5} required aria-label="Record" className="code-editor" defaultValue={'{"ticker":"AMZN","price":181.2}'} />
              </ActionForm>
            </Sheet>
          )}
          <ActionForm action={deleteDeliveryStream.bind(null, name)} submit="Delete Firehose stream" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-delivery-stream" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.firehose} size={16} />, value: <Status tone={STATUS_TONE(s.DeliveryStreamStatus)}>{s.DeliveryStreamStatus?.toLowerCase()}</Status> },
          s3?.BufferingHints && { label: "Buffer", icon: <Clock size={15} />, value: `${s3.BufferingHints.IntervalInSeconds}s / ${s3.BufferingHints.SizeInMBs} MiB` },
          s3?.CompressionFormat && s3.CompressionFormat !== "UNCOMPRESSED" && { label: "Compression", icon: <Lock size={15} />, value: s3.CompressionFormat },
          s.DeliveryStreamEncryptionConfiguration?.Status === "ENABLED" && { label: "Encryption", icon: <Lock size={15} />, value: "Encrypted" },
        ]}
      />
      <div className="flow" aria-label="Flow">
        <div className="flow-node">
          <AwsIcon icon={source ? ICONS.kinesis : "resource/Internet"} size={34} />
          <span>{source ? source.split("/").pop() : "Direct PUT"}</span>
        </div>
        <ArrowRight className="flow-arrow" size={20} aria-hidden />
        <div className="flow-node">
          <AwsIcon icon={ICONS.firehose} size={34} />
          <span>{name}</span>
        </div>
        <ArrowRight className="flow-arrow" size={20} aria-hidden />
        {d.href ? (
          <a className="flow-node" href={d.href}>
            <AwsIcon icon={d.icon} size={34} />
            <span>{d.target}</span>
          </a>
        ) : (
          <div className="flow-node">
            <AwsIcon icon={d.icon} size={34} />
            <span>{d.target || d.kind}</span>
          </div>
        )}
      </div>
    </Page>
  );
}
