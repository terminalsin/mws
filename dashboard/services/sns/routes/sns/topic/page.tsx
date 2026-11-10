import { GetTopicAttributesCommand, ListSubscriptionsByTopicCommand } from "@aws-sdk/client-sns";
import { collect, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Section, Sheet, Status } from "@mws-dashboard/ui";
import { Globe, Mail, MessageSquare, Send, Smartphone, Trash2, Unlink } from "lucide-react";
import type { Metadata } from "next";
import type { ReactNode } from "react";

import { ICONS, sns, targets } from "../../../lib/clients";
import { DEDUP_ID, GROUP_ID, MESSAGE, scopeOf, SUBJECT } from "../../../lib/rules";
import { SubscribeFields } from "../../../lib/subscribe";
import { deleteTopic, publish, subscribe, unsubscribe } from "../actions";

type Props = { searchParams: Promise<{ arn?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: shortName((await searchParams).arn) || "Topic" };
}

function protocolIcon(protocol?: string): ReactNode {
  switch (protocol) {
    case "sqs":
      return <AwsIcon icon="service/AmazonSimpleQueueService" size={24} />;
    case "lambda":
      return <AwsIcon icon="service/AWSLambda" size={24} />;
    case "firehose":
      return <AwsIcon icon="service/AmazonDataFirehose" size={24} />;
    case "email":
    case "email-json":
      return <Mail size={18} aria-hidden />;
    case "sms":
      return <MessageSquare size={18} aria-hidden />;
    case "application":
      return <Smartphone size={18} aria-hidden />;
    default:
      return <Globe size={18} aria-hidden />;
  }
}

export default async function Topic({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const data = await load(async () => {
    const client = await sns();
    const [attrs, subs, endpoints] = await Promise.all([
      client.send(new GetTopicAttributesCommand({ TopicArn: arn })),
      collect(
        (NextToken) => client.send(new ListSubscriptionsByTopicCommand({ TopicArn: arn, NextToken })),
        (r) => r.Subscriptions,
        (r) => r.NextToken,
      ),
      targets(scopeOf(arn)),
    ]);
    return { attrs: attrs.Attributes ?? {}, subs, endpoints };
  });
  const back = { href: "/sns", label: "Topics" };
  if (!data.ok) {
    return (
      <Page title={shortName(arn)} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { attrs, subs, endpoints } = data.value;
  const fifo = attrs.FifoTopic === "true";
  const dedup = fifo && attrs.ContentBasedDeduplication !== "true";
  return (
    <Page
      title={shortName(arn)}
      icon={ICONS.topic}
      back={back}
      subtitle={arn}
      actions={
        <>
          <Sheet title="Publish" label="Publish" icon={<Send size={15} aria-hidden />} testId="publish">
            <ActionForm action={publish.bind(null, arn)} submit="Publish" testId="publish">
              <div className="form-row">
                <Field label="Subject" rule={SUBJECT}>
                  <input name="subject" />
                </Field>
                {fifo && (
                  <Field label="Group ID" rule={GROUP_ID} member="MessageGroupId">
                    <input name="group" defaultValue="default" required />
                  </Field>
                )}
                {dedup && (
                  <Field label="Deduplication ID" rule={DEDUP_ID} member="MessageDeduplicationId">
                    <input name="dedup" required />
                  </Field>
                )}
              </div>
              <Field label="Message" rule={MESSAGE}>
                <textarea name="message" required />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={deleteTopic.bind(null, arn)}
            submit="Delete topic"
            icon={<Trash2 size={16} aria-hidden />}
            tone="danger"
            confirm="Delete this topic?"
          />
        </>
      }
    >
      <Section
        title="Subscriptions"
        count={subs.length}
        plain
        actions={
          <Sheet title="Subscribe" label="Subscribe" testId="subscribe">
            <ActionForm action={subscribe.bind(null, arn)} submit="Subscribe" testId="subscribe">
              <SubscribeFields topicArn={arn} fifo={fifo} targets={endpoints} />
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Subscriptions"
          empty={<Empty icon={ICONS.topic} />}
          rows={subs.map((s) => ({
            key: s.SubscriptionArn! + s.Endpoint,
            icon: protocolIcon(s.Protocol),
            title: s.Endpoint,
            subtitle: s.Protocol,
            meta: s.SubscriptionArn === "PendingConfirmation" ? <Status tone="warn">pending</Status> : <Status tone="good">confirmed</Status>,
            actions:
              s.SubscriptionArn !== "PendingConfirmation" ? (
                <ActionForm
                  action={unsubscribe.bind(null, s.SubscriptionArn!)}
                  submit={`Unsubscribe ${s.Endpoint}`}
                  icon={<Unlink size={16} aria-hidden />}
                  tone="danger"
                />
              ) : undefined,
          }))}
        />
      </Section>
      <Section>
        <Facts
          items={[
            attrs.DisplayName && ["Display name", attrs.DisplayName],
            ["Encryption", attrs.KmsMasterKeyId ?? "None"],
            fifo && ["Content-based dedup", attrs.ContentBasedDeduplication],
            attrs.DeliveryPolicy && ["Delivery policy", "custom"],
          ]}
        />
      </Section>
      {attrs.Policy && (
        <Section title="Access policy">
          <CodeBlock value={attrs.Policy} />
        </Section>
      )}
    </Page>
  );
}
