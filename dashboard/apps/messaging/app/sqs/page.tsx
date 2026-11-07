import { GetQueueAttributesCommand, ListQueuesCommand } from "@aws-sdk/client-sqs";
import { collect, load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, Field, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { queueName, sqs } from "../../lib/clients";
import { createQueue } from "./actions";

export const metadata: Metadata = { title: "SQS queues" };

export default async function Queues() {
  const queues = await load(async () => {
    const client = await sqs();
    const urls = await collect(
      (NextToken) => client.send(new ListQueuesCommand({ NextToken, MaxResults: 1000 })),
      (r) => r.QueueUrls,
      (r) => r.NextToken,
    );
    return Promise.all(
      urls.map(async (url) => {
        const attrs = (await client.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ["All"] }))).Attributes ?? {};
        return { url, name: queueName(url), attrs };
      }),
    );
  });
  return (
    <>
      <PageHeader title="SQS queues" description="Queues in the selected region, with their approximate message counts." />
      <Section title="Create queue">
        <ActionForm action={createQueue} submit="Create queue" inline testId="create-queue">
          <Field label="Queue name">
            <input name="name" required maxLength={80} pattern="[A-Za-z0-9_\-]+(\.fifo)?" />
          </Field>
          <label className="check">
            <input type="checkbox" name="fifo" /> FIFO
          </label>
          <label className="check">
            <input type="checkbox" name="dedup" /> Content-based deduplication
          </label>
        </ActionForm>
      </Section>
      <Section title={queues.ok ? `Queues (${queues.value.length})` : "Queues"}>
        {queues.ok ? (
          <Table
            label="Queues"
            rows={queues.value}
            rowKey={(q) => q.url}
            empty="No queues in this region."
            columns={[
              { header: "Name", cell: (q) => <Link href={`/sqs/${encodeURIComponent(q.name)}`}>{q.name}</Link> },
              { header: "Type", cell: (q) => (q.attrs.FifoQueue === "true" ? <Badge tone="info">FIFO</Badge> : <Badge>Standard</Badge>) },
              { header: "Available", className: "num", cell: (q) => q.attrs.ApproximateNumberOfMessages ?? "0" },
              { header: "In flight", className: "num", cell: (q) => q.attrs.ApproximateNumberOfMessagesNotVisible ?? "0" },
              { header: "Delayed", className: "num", cell: (q) => q.attrs.ApproximateNumberOfMessagesDelayed ?? "0" },
              { header: "Created", cell: (q) => when(Number(q.attrs.CreatedTimestamp) * 1000) },
            ]}
          />
        ) : (
          <ErrorNotice error={queues.error} />
        )}
      </Section>
    </>
  );
}
