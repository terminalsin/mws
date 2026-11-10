import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, type Rule } from "@mws-dashboard/ui";
import { ArrowRight } from "lucide-react";
import { CreateQueue as CreateQueueRules } from "@mws-dashboard/ui/model/sqs";
import type { Metadata } from "next";

import { ICONS, isDlq, queues, type QueueInfo } from "../../lib/clients";
import { createQueue } from "./actions";

export const metadata: Metadata = { title: "SQS" };

// SQS's model leaves the queue name unconstrained; the rules are in its docs.
const QUEUE_NAME: Rule = {
  ...CreateQueueRules.QueueName,
  pattern: "^[A-Za-z0-9_-]{1,80}$|^[A-Za-z0-9_-]{1,75}\\.fifo$", hint: "Letters, digits, - and _", generate: "name",
};

function CreateQueue({ dlqs, names }: { dlqs: QueueInfo[]; names: string[] }) {
  return (
    <Sheet title="New queue" label="Create queue" testId="create-queue">
      <ActionForm action={createQueue} submit="Create" testId="create-queue">
        <Field label="Name" rule={QUEUE_NAME} taken={names} unique>
          <input name="name" required maxLength={80} autoFocus />
        </Field>
        <div className="form-row">
          <label className="check">
            <input type="checkbox" name="fifo" /> FIFO
          </label>
          <label className="check">
            <input type="checkbox" name="dedup" /> Content-based deduplication
          </label>
        </div>
        {dlqs.length > 0 && (
          <div className="form-row">
            <Field label="Dead-letter queue">
              <select name="dlq" defaultValue="">
                <option value="">None</option>
                {dlqs.map((q) => (
                  <option key={q.arn} value={q.arn}>
                    {q.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Max receives">
              <input name="maxReceiveCount" type="number" min="1" max="1000" defaultValue="5" />
            </Field>
          </div>
        )}
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
  const dlqs = all.filter(isDlq);
  const sections = [
    { id: "work", title: "Queues", items: all.filter((q) => !isDlq(q)) },
    { id: "dlq", title: "Dead-letter queues", items: dlqs },
  ].filter((s) => s.items.length);
  return (
    <Page title="Queues" actions={<CreateQueue dlqs={all} names={all.map((q) => q.name)} />}>
      <Curated
        label="Queues"
        sections={sections}
        empty={<Empty icon={ICONS.queue} action={<CreateQueue dlqs={[]} names={[]} />} />}
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
                <ArrowRight size={11} aria-hidden /> {q.dlq}
              </>
            ) : q.sources.length ? (
              `from ${q.sources.join(", ")}`
            ) : undefined,
            href: `/sqs/${encodeURIComponent(q.name)}`,
            meta: (
              <>
                {q.attrs.FifoQueue === "true" && <Pill tone="info">FIFO</Pill>}
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
