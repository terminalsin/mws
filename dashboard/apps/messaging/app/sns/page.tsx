import { GetTopicAttributesCommand, ListTopicsCommand } from "@aws-sdk/client-sns";
import { collect, load, shortName, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, Field, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { sns } from "../../lib/clients";
import { snsEmails, snsSms } from "../../lib/outbox";
import { clearOutbox, createTopic } from "./actions";

export const metadata: Metadata = { title: "SNS topics" };

export default async function Topics() {
  const [topics, emails, sms] = await Promise.all([
    load(async () => {
      const client = await sns();
      const arns = await collect(
        (NextToken) => client.send(new ListTopicsCommand({ NextToken })),
        (r) => r.Topics?.map((t) => t.TopicArn!),
        (r) => r.NextToken,
      );
      return Promise.all(
        arns.map(async (arn) => ({ arn, attrs: (await client.send(new GetTopicAttributesCommand({ TopicArn: arn }))).Attributes ?? {} })),
      );
    }),
    load(snsEmails),
    load(snsSms),
  ]);
  return (
    <>
      <PageHeader title="SNS topics" description="Topics in the selected region, and the email and SMS messages SNS delivered." />
      <Section title="Create topic">
        <ActionForm action={createTopic} submit="Create topic" inline testId="create-topic">
          <Field label="Topic name">
            <input name="name" required maxLength={256} pattern="[A-Za-z0-9_\-]+(\.fifo)?" />
          </Field>
          <label className="check">
            <input type="checkbox" name="fifo" /> FIFO
          </label>
        </ActionForm>
      </Section>
      <Section title={topics.ok ? `Topics (${topics.value.length})` : "Topics"}>
        {topics.ok ? (
          <Table
            label="Topics"
            rows={topics.value}
            rowKey={(t) => t.arn}
            empty="No topics in this region."
            columns={[
              {
                header: "Name",
                cell: (t) => <Link href={`/sns/topic?arn=${encodeURIComponent(t.arn)}`}>{shortName(t.arn)}</Link>,
              },
              { header: "Type", cell: (t) => (t.attrs.FifoTopic === "true" ? <Badge tone="info">FIFO</Badge> : <Badge>Standard</Badge>) },
              { header: "Confirmed", className: "num", cell: (t) => t.attrs.SubscriptionsConfirmed ?? "0" },
              { header: "Pending", className: "num", cell: (t) => t.attrs.SubscriptionsPending ?? "0" },
              { header: "Encryption", cell: (t) => t.attrs.KmsMasterKeyId ?? "none" },
            ]}
          />
        ) : (
          <ErrorNotice error={topics.error} />
        )}
      </Section>
      <Section
        title="Email outbox"
        actions={<ActionForm action={clearOutbox.bind(null, "email-messages")} submit="Clear" tone="danger" inline />}
      >
        {emails.ok ? (
          <Table
            label="SNS email"
            rows={[...emails.value].reverse()}
            rowKey={(m) => m.messageId}
            empty="SNS has not emailed anyone."
            columns={[
              { header: "Sent", cell: (m) => when(m.timestamp) },
              { header: "To", cell: (m) => m.to },
              { header: "Topic", cell: (m) => shortName(m.topicArn) },
              {
                header: "Message",
                className: "wrap",
                cell: (m) => (
                  <details>
                    <summary>{m.subject || "(no subject)"}</summary>
                    <pre className="code">{m.body}</pre>
                  </details>
                ),
              },
            ]}
          />
        ) : (
          <ErrorNotice error={emails.error} />
        )}
      </Section>
      <Section title="SMS outbox" actions={<ActionForm action={clearOutbox.bind(null, "sms-messages")} submit="Clear" tone="danger" inline />}>
        {sms.ok ? (
          <Table
            label="SNS SMS"
            rows={[...sms.value].reverse()}
            rowKey={(m) => m.messageId}
            empty="SNS has not sent any text messages."
            columns={[
              { header: "Sent", cell: (m) => when(m.timestamp) },
              { header: "To", cell: (m) => m.phoneNumber },
              { header: "Message", className: "wrap", cell: (m) => m.message },
            ]}
          />
        ) : (
          <ErrorNotice error={sms.error} />
        )}
      </Section>
    </>
  );
}
