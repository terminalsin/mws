import { GetTopicAttributesCommand, ListTopicsCommand } from "@aws-sdk/client-sns";
import { sections } from "@mws-dashboard/ai";
import { ago, collect, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { Eraser, Mail, MessageSquare } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, sns } from "../../lib/clients";
import { snsEmails, snsSms } from "../../lib/outbox";
import { TOPIC_NAME } from "../../lib/rules";
import { clearOutbox, createTopic } from "./actions";

export const metadata: Metadata = { title: "SNS" };

type Props = { searchParams: Promise<{ tab?: string }> };

const TOPIC_KINDS = [
  { id: "alerts", title: "Alerts & alarms", prototype: "alerts alarms alarm notifications pager oncall incidents ops monitoring", rule: /(alert|alarm|page|oncall|incident|ops|monitor)/i },
  { id: "events", title: "Domain events", prototype: "events created updated deleted orders users payments changes", rule: /(event|created|updated|deleted|changed)/i },
];

function CreateTopic({ names = [] }: { names?: string[] }) {
  return (
    <Sheet title="New topic" label="Create topic" testId="create-topic">
      <ActionForm action={createTopic} submit="Create" testId="create-topic">
        <Field label="Name" rule={TOPIC_NAME} taken={names} unique>
          <input name="name" required maxLength={256} autoFocus />
        </Field>
        <label className="check">
          <input type="checkbox" name="fifo" /> FIFO
        </label>
      </ActionForm>
    </Sheet>
  );
}

async function topicArns() {
  const client = await sns();
  return collect(
    (NextToken) => client.send(new ListTopicsCommand({ NextToken })),
    (r) => r.Topics?.map((t) => t.TopicArn!),
    (r) => r.NextToken,
  );
}

async function Topics() {
  const topics = await load(async () => {
    const client = await sns();
    const arns = await topicArns();
    const list = await Promise.all(
      arns.map(async (arn) => ({ arn, text: shortName(arn), attrs: (await client.send(new GetTopicAttributesCommand({ TopicArn: arn }))).Attributes ?? {} })),
    );
    return sections(list, TOPIC_KINDS, "Topics");
  });
  if (!topics.ok) return <ErrorNotice error={topics.error} />;
  return (
    <Curated
      label="Topics"
      sections={topics.value}
      empty={<Empty icon={ICONS.topic} action={<CreateTopic />} />}
      row={(t) => {
        const confirmed = Number(t.attrs.SubscriptionsConfirmed ?? 0);
        const pending = Number(t.attrs.SubscriptionsPending ?? 0);
        return {
          key: t.arn,
          icon: <AwsIcon icon={ICONS.topic} size={24} />,
          title: shortName(t.arn),
          href: `/sns/topic?arn=${encodeURIComponent(t.arn)}`,
          meta: (
            <>
              {t.attrs.FifoTopic === "true" && <Pill tone="info">FIFO</Pill>}
              {t.attrs.KmsMasterKeyId && <Pill>KMS</Pill>}
              {pending > 0 && <Pill tone="warn">{pending} pending</Pill>}
              <Pill title="Subscriptions">{confirmed}</Pill>
            </>
          ),
        };
      }}
    />
  );
}

async function Outbox() {
  const [emails, sms] = await Promise.all([load(snsEmails), load(snsSms)]);
  return (
    <>
      <Section
        title="Email"
        count={emails.ok ? emails.value.length : undefined}
        plain
        actions={
          <ActionForm action={clearOutbox.bind(null, "email-messages")} submit="Clear email" icon={<Eraser size={16} aria-hidden />} tone="danger" />
        }
      >
        {emails.ok ? (
          <List
            label="SNS email"
            empty={<Empty>—</Empty>}
            rows={[...emails.value].reverse().map((m) => ({
              key: m.messageId,
              icon: <Mail size={18} aria-hidden />,
              title: m.subject || shortName(m.topicArn),
              subtitle: (
                <details>
                  <summary>{m.to}</summary>
                  <pre className="code">{m.body}</pre>
                </details>
              ),
              meta: ago(m.timestamp),
            }))}
          />
        ) : (
          <ErrorNotice error={emails.error} />
        )}
      </Section>
      <Section
        title="SMS"
        count={sms.ok ? sms.value.length : undefined}
        plain
        actions={<ActionForm action={clearOutbox.bind(null, "sms-messages")} submit="Clear SMS" icon={<Eraser size={16} aria-hidden />} tone="danger" />}
      >
        {sms.ok ? (
          <List
            label="SNS SMS"
            empty={<Empty>—</Empty>}
            rows={[...sms.value].reverse().map((m) => ({
              key: m.messageId,
              icon: <MessageSquare size={18} aria-hidden />,
              title: m.phoneNumber,
              subtitle: m.message,
              meta: ago(m.timestamp),
            }))}
          />
        ) : (
          <ErrorNotice error={sms.error} />
        )}
      </Section>
    </>
  );
}

export default async function Sns({ searchParams }: Props) {
  const tab = (await searchParams).tab ?? "topics";
  const names = tab === "topics" ? await topicArns().then((arns) => arns.map((a) => shortName(a)), () => []) : [];
  return (
    <Page title={tab === "outbox" ? "Deliveries" : "Topics"} actions={tab === "topics" ? <CreateTopic names={names} /> : undefined}>
      {tab === "outbox" ? <Outbox /> : <Topics />}
    </Page>
  );
}
