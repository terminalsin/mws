import { DescribeStreamSummaryCommand, GetRecordsCommand, GetShardIteratorCommand, ListShardsCommand } from "@aws-sdk/client-kinesis";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { Clock, Layers, Lock, Send, SlidersHorizontal, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, kinesis } from "../../../lib/clients";
import { deleteStream, putRecord, reshard } from "../actions";

export const metadata: Metadata = { title: "Data stream" };

type Props = { searchParams: Promise<{ name?: string }> };

export default async function Stream({ searchParams }: Props) {
  const { name = "" } = await searchParams;
  const back = { href: "/kinesis", label: "Data streams" };
  const data = await load(async () => {
    const client = await kinesis();
    const [summary, shards] = await Promise.all([
      client.send(new DescribeStreamSummaryCommand({ StreamName: name })).then((r) => r.StreamDescriptionSummary!),
      client.send(new ListShardsCommand({ StreamName: name })).then((r) => r.Shards ?? [], () => []),
    ]);
    // The data viewer: the newest records of each open shard.
    const open = shards.filter((s) => !s.SequenceNumberRange?.EndingSequenceNumber);
    const records = (
      await Promise.all(
        open.map(async (s) => {
          try {
          const it = await client.send(new GetShardIteratorCommand({ StreamName: name, ShardId: s.ShardId, ShardIteratorType: "TRIM_HORIZON" }));
          const r = await client.send(new GetRecordsCommand({ ShardIterator: it.ShardIterator, Limit: 1000 }));
          return (r.Records ?? []).map((x) => ({ ...x, shard: s.ShardId! }));
          } catch {
            return [];
          }
        }),
      )
    )
      .flat()
      .sort((a, b) => (b.ApproximateArrivalTimestamp?.getTime() ?? 0) - (a.ApproximateArrivalTimestamp?.getTime() ?? 0))
      .slice(0, 25);
    return { summary, shards, records };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.kinesis} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { summary: s, shards, records } = data.value;
  const provisioned = s.StreamModeDetails?.StreamMode !== "ON_DEMAND";
  return (
    <Page
      title={name}
      icon={ICONS.kinesis}
      back={back}
      subtitle={s.StreamARN}
      actions={
        <>
          <Sheet title="Put record" label="Put record" icon={<Send size={16} />} testId="put-record">
            <ActionForm action={putRecord.bind(null, name)} submit="Put record" testId="put-record">
              <Field label="Partition key">
                <input name="key" placeholder="random" />
              </Field>
              <textarea name="data" rows={5} required aria-label="Data" className="code-editor" defaultValue={'{\n  "event": "hello"\n}'} />
            </ActionForm>
          </Sheet>
          {provisioned && (
            <Sheet title="Reshard" label="Reshard" icon={<SlidersHorizontal size={16} />} testId="reshard">
              <ActionForm action={reshard.bind(null, name)} submit="Update" testId="reshard">
                <Field label="Open shards">
                  <input name="shards" type="number" min={1} defaultValue={s.OpenShardCount} />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          <ActionForm action={deleteStream.bind(null, name)} submit="Delete stream" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-stream" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.kinesis} size={16} />, value: <Status tone={STATUS_TONE(s.StreamStatus)}>{s.StreamStatus?.toLowerCase()}</Status> },
          { label: "Capacity mode", icon: <SlidersHorizontal size={15} />, value: provisioned ? "Provisioned" : "On-demand" },
          { label: "Open shards", icon: <Layers size={15} />, value: s.OpenShardCount },
          { label: "Retention", icon: <Clock size={15} />, value: `${s.RetentionPeriodHours}h` },
          s.EncryptionType === "KMS" && { label: "Encryption", icon: <Lock size={15} />, value: "KMS" },
        ]}
      />
      <Section title="Data viewer" count={records.length} plain>
        <List
          label="Records"
          empty={<div className="empty">No records</div>}
          rows={records.map((r) => {
            const text = new TextDecoder().decode(r.Data);
            return {
              key: r.SequenceNumber!,
              icon: <Pill>{r.PartitionKey?.slice(0, 12)}</Pill>,
              title: <code className="clip">{text.replace(/\s+/g, " ")}</code>,
              subtitle: `${r.shard} · ${r.SequenceNumber}`,
              meta: <span>{ago(r.ApproximateArrivalTimestamp)}</span>,
            };
          })}
        />
      </Section>
      <Section title="Shards" count={shards.length} plain>
        <List
          label="Shards"
          rows={shards.map((sh) => ({
            key: sh.ShardId!,
            icon: <Layers size={18} />,
            title: sh.ShardId,
            subtitle: sh.ParentShardId ? `from ${sh.ParentShardId}` : undefined,
            meta: <Status tone={sh.SequenceNumberRange?.EndingSequenceNumber ? "neutral" : "good"}>{sh.SequenceNumberRange?.EndingSequenceNumber ? "Closed" : "Open"}</Status>,
          }))}
        />
      </Section>
    </Page>
  );
}
