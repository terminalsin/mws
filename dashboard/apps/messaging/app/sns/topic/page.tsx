import { GetTopicAttributesCommand, ListSubscriptionsByTopicCommand } from "@aws-sdk/client-sns";
import { collect, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, Badge, CodeBlock, ErrorNotice, Field, KeyValue, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { sns } from "../../../lib/clients";
import { deleteTopic, publish, subscribe, unsubscribe } from "../actions";

type Props = { searchParams: Promise<{ arn?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: shortName((await searchParams).arn) || "Topic" };
}

const PROTOCOLS = ["sqs", "lambda", "email", "email-json", "sms", "http", "https", "firehose", "application"];

export default async function Topic({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const data = await load(async () => {
    const client = await sns();
    const [attrs, subs] = await Promise.all([
      client.send(new GetTopicAttributesCommand({ TopicArn: arn })),
      collect(
        (NextToken) => client.send(new ListSubscriptionsByTopicCommand({ TopicArn: arn, NextToken })),
        (r) => r.Subscriptions,
        (r) => r.NextToken,
      ),
    ]);
    return { attrs: attrs.Attributes ?? {}, subs };
  });
  const crumbs = [{ label: "SNS topics", href: "/sns" }];
  if (!data.ok) {
    return (
      <>
        <PageHeader title={shortName(arn)} crumbs={crumbs} />
        <ErrorNotice error={data.error} />
      </>
    );
  }
  const { attrs, subs } = data.value;
  const fifo = attrs.FifoTopic === "true";
  return (
    <>
      <PageHeader title={shortName(arn)} crumbs={crumbs} description={<code>{arn}</code>} />
      <Section title="Publish">
        <ActionForm action={publish.bind(null, arn)} submit="Publish" testId="publish">
          <div className="form-row">
            <Field label="Subject">
              <input name="subject" />
            </Field>
            {fifo && (
              <Field label="Message group ID">
                <input name="group" defaultValue="default" required />
              </Field>
            )}
          </div>
          <Field label="Message">
            <textarea name="message" required />
          </Field>
        </ActionForm>
      </Section>
      <Section title={`Subscriptions (${subs.length})`}>
        <Table
          label="Subscriptions"
          rows={subs}
          rowKey={(s) => s.SubscriptionArn!}
          empty="No subscriptions."
          columns={[
            { header: "Protocol", cell: (s) => <Badge>{s.Protocol}</Badge> },
            { header: "Endpoint", className: "wrap", cell: (s) => <code>{s.Endpoint}</code> },
            {
              header: "Status",
              cell: (s) =>
                s.SubscriptionArn === "PendingConfirmation" ? <Badge tone="warn">pending</Badge> : <Badge tone="good">confirmed</Badge>,
            },
            {
              header: "",
              cell: (s) =>
                s.SubscriptionArn !== "PendingConfirmation" && (
                  <ActionForm action={unsubscribe.bind(null, s.SubscriptionArn!)} submit="Unsubscribe" tone="danger" inline />
                ),
            },
          ]}
        />
        <div style={{ marginTop: 12 }}>
          <ActionForm action={subscribe.bind(null, arn)} submit="Subscribe" inline testId="subscribe">
            <Field label="Protocol">
              <select name="protocol" defaultValue="sqs">
                {PROTOCOLS.map((p) => (
                  <option key={p}>{p}</option>
                ))}
              </select>
            </Field>
            <Field label="Endpoint" hint="A queue or function ARN, an address, a number or a URL">
              <input name="endpoint" required size={48} />
            </Field>
            <label className="check">
              <input type="checkbox" name="grant" defaultChecked /> For SQS, allow the topic in the queue policy
            </label>
          </ActionForm>
        </div>
      </Section>
      <Section title="Attributes">
        <KeyValue
          items={[
            ["Display name", attrs.DisplayName || "—"],
            ["Owner", attrs.Owner],
            ["Encryption", attrs.KmsMasterKeyId ?? "none"],
            ["Content-based dedup", attrs.ContentBasedDeduplication ?? "—"],
          ]}
        />
        {attrs.Policy && (
          <>
            <h2 style={{ margin: "16px 0 8px" }}>Access policy</h2>
            <CodeBlock value={attrs.Policy} />
          </>
        )}
      </Section>
      <Section title="Delete">
        <ActionForm action={deleteTopic.bind(null, arn)} submit="Delete topic" tone="danger" confirm="Delete this topic?" inline />
      </Section>
    </>
  );
}
