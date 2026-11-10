import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Page, Pill, Sheet } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { ArrowRight } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, isDlq, queues, type QueueInfo } from "../../lib/clients";
import { arnName } from "../../lib/links";
import { CreateQueueFields } from "../../lib/create";
import { createQueue } from "./actions";

export const metadata: Metadata = { title: "SQS" };

function CreateQueue({ all }: { all: QueueInfo[] }) {
  return (
    <Sheet title="New queue" label="Create queue" testId="create-queue">
      <ActionForm action={createQueue} submit="Create" testId="create-queue">
        <CreateQueueFields queues={all.map((q) => ({ name: q.name, arn: q.arn, fifo: q.attrs.FifoQueue === "true" }))} />
      </ActionForm>
    </Sheet>
  );
}

export default async function Queues() {
  const list = await load(queues);
  if (!list.ok) {
    return (
      <Page title="Queues">
        <ErrorNotice error={list.error} />
      </Page>
    );
  }
  const all = list.value.sort((a, b) => a.name.localeCompare(b.name));
  const sections = [
    { id: "work", title: "Queues", items: all.filter((q) => !isDlq(q)) },
    { id: "dlq", title: "Dead-letter queues", items: all.filter(isDlq) },
  ].filter((s) => s.items.length);
  const busy = all.some((q) => Number(q.attrs.ApproximateNumberOfMessagesNotVisible ?? 0) > 0 || Number(q.attrs.ApproximateNumberOfMessagesDelayed ?? 0) > 0);
  return (
    <Page title="Queues" actions={<CreateQueue all={all} />}>
      <LiveRefresh when={busy} />
      <Curated
        label="Queues"
        sections={sections}
        empty={<Empty icon={ICONS.queue} action={<CreateQueue all={[]} />} />}
        row={(q) => {
          const visible = Number(q.attrs.ApproximateNumberOfMessages ?? 0);
          const inflight = Number(q.attrs.ApproximateNumberOfMessagesNotVisible ?? 0);
          const dlq = isDlq(q);
          return {
            key: q.url,
            icon: <AwsIcon icon={ICONS.queue} size={24} />,
            title: q.name,
            subtitle: q.dlq ? (
              <>
                <ArrowRight size={11} aria-hidden /> {arnName(q.dlq)}
              </>
            ) : q.sources.length ? (
              `from ${q.sources.map(arnName).join(", ")}`
            ) : undefined,
            href: `/sqs/${encodeURIComponent(q.name)}`,
            meta: (
              <>
                {q.attrs.FifoQueue === "true" && <Pill tone="info">FIFO</Pill>}
                {!q.attrs.KmsMasterKeyId && q.attrs.SqsManagedSseEnabled !== "true" && <Pill tone="warn" title="Not encrypted">unencrypted</Pill>}
                {inflight > 0 && <Pill title="In flight">{inflight} in flight</Pill>}
                <Pill tone={dlq && visible > 0 ? "bad" : visible > 0 ? "info" : "neutral"} title="Available">
                  {visible}
                </Pill>
                <span>{ago(Number(q.attrs.CreatedTimestamp))}</span>
              </>
            ),
          };
        }}
      />
    </Page>
  );
}
