import { GetSubscriptionAttributesCommand } from "@aws-sdk/client-sns";
import { load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Facts, Field, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { Settings2, Unlink } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, sns } from "../../../lib/clients";
import { arnHref, arnName } from "../../../lib/links";
import { DLQ_ARN, FILTER_POLICY, JSON_POLICY } from "../../../lib/rules";
import { Endpoint } from "../../../lib/view";
import { saveSubscription, unsubscribe } from "../actions";

type Props = { searchParams: Promise<{ arn?: string }> };

export const metadata: Metadata = { title: "Subscription" };

const RAW = ["sqs", "http", "https", "firehose"];

const pretty = (v?: string) => {
  if (!v) return "";
  try {
    return JSON.stringify(JSON.parse(v), null, 2);
  } catch {
    return v;
  }
};

export default async function SubscriptionPage({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const topicArn = arn.split(":").slice(0, 6).join(":");
  const back = { href: `/sns/topic?arn=${encodeURIComponent(topicArn)}`, label: arnName(topicArn) };
  const data = await load(async () => (await (await sns()).send(new GetSubscriptionAttributesCommand({ SubscriptionArn: arn }))).Attributes ?? {});
  if (!data.ok) {
    return (
      <Page title="Subscription" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const a = data.value;
  const protocol = a.Protocol ?? "";
  let dlq: string | undefined;
  try {
    dlq = a.RedrivePolicy ? JSON.parse(a.RedrivePolicy).deadLetterTargetArn : undefined;
  } catch {
    // malformed
  }
  const waiting = a.PendingConfirmation === "true";
  const link = (target?: string) => (target && arnHref(target) ? <Link href={arnHref(target)!}>{arnName(target)}</Link> : target);
  return (
    <Page
      title={arn.split(":").pop()}
      icon={ICONS.topic}
      back={back}
      subtitle={arn}
      actions={
        <>
          <Sheet title="Subscription" label="Edit subscription" icon={<Settings2 size={15} aria-hidden />} testId="edit-subscription">
            <ActionForm action={saveSubscription.bind(null, arn, protocol)} submit="Save" testId="edit-subscription">
              <div className="form-row">
                <Field label="Filter policy" rule={FILTER_POLICY} member="FilterPolicy">
                  <textarea name="filter" rows={5} spellCheck={false} defaultValue={pretty(a.FilterPolicy)} />
                </Field>
                <Field label="Filter on">
                  <select name="filterScope" defaultValue={a.FilterPolicyScope ?? "MessageAttributes"}>
                    <option value="MessageAttributes">Message attributes</option>
                    <option value="MessageBody">Message body</option>
                  </select>
                </Field>
              </div>
              {RAW.includes(protocol) && (
                <label className="check">
                  <input type="checkbox" name="raw" defaultChecked={a.RawMessageDelivery === "true"} /> Raw message delivery
                </label>
              )}
              <Field label="Dead-letter queue" rule={DLQ_ARN} member="RedrivePolicy">
                <input name="dlq" defaultValue={dlq} spellCheck={false} />
              </Field>
              {(protocol === "http" || protocol === "https") && (
                <Field label="Delivery policy" rule={JSON_POLICY} member="DeliveryPolicy">
                  <textarea name="deliveryPolicy" rows={4} spellCheck={false} defaultValue={pretty(a.DeliveryPolicy)} />
                </Field>
              )}
            </ActionForm>
          </Sheet>
          <ActionForm action={unsubscribe.bind(null, arn)} submit="Unsubscribe" icon={<Unlink size={16} aria-hidden />} tone="danger" confirm="Delete this subscription?" />
        </>
      }
    >
      <Section>
        <Facts
          items={[
            ["Status", waiting ? <Status key="s" tone="warn">pending</Status> : <Status key="s" tone="good">confirmed</Status>],
            ["Protocol", protocol],
            ["Endpoint", <Endpoint key="e" sub={{ Endpoint: a.Endpoint, Protocol: protocol }} />],
            ["Topic", link(topicArn)],
            RAW.includes(protocol) && ["Raw message delivery", a.RawMessageDelivery === "true" ? <Pill key="r" tone="info">on</Pill> : "off"],
            dlq && ["Dead-letter queue", link(dlq)],
            a.SubscriptionRoleArn && ["Role", link(a.SubscriptionRoleArn)],
            a.ConfirmationWasAuthenticated === "true" && ["Confirmation", "authenticated"],
            ["Owner", a.Owner],
          ]}
        />
      </Section>
      {a.FilterPolicy && (
        <Section title={`Filter policy · ${a.FilterPolicyScope === "MessageBody" ? "message body" : "message attributes"}`}>
          <CodeBlock value={a.FilterPolicy} label="Filter policy" />
        </Section>
      )}
      {a.EffectiveDeliveryPolicy && (protocol === "http" || protocol === "https") && (
        <Section title="Effective delivery policy">
          <CodeBlock value={a.EffectiveDeliveryPolicy} />
        </Section>
      )}
    </Page>
  );
}
