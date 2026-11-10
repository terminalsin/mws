import { GetTopicAttributesCommand, ListSubscriptionsByTopicCommand, ListTagsForResourceCommand } from "@aws-sdk/client-sns";
import { all, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Status, Tags } from "@mws-dashboard/ui";
import { CheckCheck, FileClock, Send, Settings2, Tag, Trash2, Unlink } from "lucide-react";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, sns, targets } from "../../../lib/clients";
import { arnHref, arnName } from "../../../lib/links";
import { ACCESS_POLICY, DEDUP_ID, DISPLAY_NAME, GROUP_ID, JSON_POLICY, KMS_KEY, MESSAGE, MESSAGE_ATTRIBUTES, RETENTION_DAYS, SAMPLE_RATE, scopeOf, SUBJECT } from "../../../lib/rules";
import { SubscribeFields } from "../../../lib/subscribe";
import { Endpoint, pending, protocolIcon } from "../../../lib/view";
import { confirmPending, deleteTopic, publish, saveLogging, saveTopic, saveTopicTags, subscribe, unsubscribe } from "../actions";

type Props = { searchParams: Promise<{ arn?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: shortName((await searchParams).arn) || "Topic" };
}

const LOGGED = ["SQS", "Lambda", "HTTP", "Firehose", "Application"];

const pretty = (v?: string) => {
  if (!v) return "";
  try {
    return JSON.stringify(JSON.parse(v), null, 2);
  } catch {
    return v;
  }
};

export default async function Topic({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const data = await load(async () => {
    const client = await sns();
    const [attrs, subs, endpoints, tags] = await Promise.all([
      client.send(new GetTopicAttributesCommand({ TopicArn: arn })),
      all(
        (NextToken) => client.send(new ListSubscriptionsByTopicCommand({ TopicArn: arn, NextToken })),
        (r) => r.Subscriptions,
        (r) => r.NextToken,
      ),
      targets(scopeOf(arn)),
      client.send(new ListTagsForResourceCommand({ ResourceArn: arn })).then((r) => r.Tags ?? [], () => []),
    ]);
    return { attrs: attrs.Attributes ?? {}, subs, endpoints, tags };
  });
  const back = { href: "/sns", label: "Topics" };
  if (!data.ok) {
    return (
      <Page title={shortName(arn)} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { attrs, subs, endpoints, tags } = data.value;
  const fifo = attrs.FifoTopic === "true";
  const dedup = fifo && attrs.ContentBasedDeduplication !== "true";
  let archiveDays: string | undefined;
  try {
    archiveDays = attrs.ArchivePolicy ? String(JSON.parse(attrs.ArchivePolicy).MessageRetentionPeriod) : undefined;
  } catch {
    // malformed
  }
  const logging = LOGGED.filter((p) => attrs[`${p}SuccessFeedbackRoleArn`] || attrs[`${p}FailureFeedbackRoleArn`]);
  const tagKeys = tags.map((t) => t.Key!);
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
              <MoreFields label="Attributes, per-protocol messages">
                <Field label="Message attributes" rule={MESSAGE_ATTRIBUTES} member="MessageAttributes">
                  <textarea name="attributes" rows={3} placeholder={"type=order\nprice:Number=10"} spellCheck={false} />
                </Field>
                <label className="check">
                  <input type="checkbox" name="structure" value="json" /> Different message per protocol (JSON with a &quot;default&quot; key)
                </label>
              </MoreFields>
            </ActionForm>
          </Sheet>
          <Sheet title="Topic settings" label="Edit topic" icon={<Settings2 size={15} aria-hidden />} testId="edit-topic">
            <ActionForm action={saveTopic.bind(null, arn)} submit="Save" testId="edit-topic">
              <Field label="Display name" rule={DISPLAY_NAME} member="DisplayName">
                <input name="displayName" defaultValue={attrs.DisplayName} />
              </Field>
              <div className="form-row">
                <label className="check">
                  <input type="checkbox" name="encryption" defaultChecked={!!attrs.KmsMasterKeyId} /> Encryption
                </label>
                <Field label="KMS key" rule={KMS_KEY} member="KmsMasterKeyId">
                  <input name="kmsKey" defaultValue={attrs.KmsMasterKeyId ?? "alias/aws/sns"} spellCheck={false} />
                </Field>
              </div>

              {fifo && (
                <div className="form-row">
                  <label className="check">
                    <input type="checkbox" name="dedup" defaultChecked={attrs.ContentBasedDeduplication === "true"} /> Content-based deduplication
                  </label>
                  <Field label="Archive (days)" rule={RETENTION_DAYS} member="ArchivePolicy">
                    <input name="archive" inputMode="numeric" defaultValue={archiveDays} />
                  </Field>
                </div>
              )}
              <MoreFields label="Policies, tracing">
                <Field label="Access policy" rule={ACCESS_POLICY} member="Policy">
                  <textarea name="policy" rows={8} spellCheck={false} defaultValue={pretty(attrs.Policy)} />
                </Field>
                <Field label="Delivery policy (HTTP/S)" rule={JSON_POLICY} member="DeliveryPolicy">
                  <textarea name="deliveryPolicy" rows={4} spellCheck={false} defaultValue={pretty(attrs.DeliveryPolicy)} />
                </Field>
                <label className="check">
                  <input type="checkbox" name="tracing" defaultChecked={attrs.TracingConfig === "Active"} /> Active tracing
                </label>
              </MoreFields>
            </ActionForm>
          </Sheet>
          <Sheet title="Delivery status logging" label="Delivery status logging" icon={<FileClock size={15} aria-hidden />} testId="topic-logging">
            <ActionForm action={saveLogging.bind(null, arn)} submit="Save" testId="topic-logging">
              <Field label="Protocol">
                <select name="protocol" defaultValue={logging[0] ?? "SQS"}>
                  {LOGGED.map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </Field>
              <div className="form-row">
                <Field label="Success role" format="arn" known={endpoints.roles}>
                  <input name="successRole" spellCheck={false} />
                </Field>
                <Field label="Failure role" format="arn" known={endpoints.roles}>
                  <input name="failureRole" spellCheck={false} />
                </Field>
                <Field label="Success sample rate (%)" rule={SAMPLE_RATE}>
                  <input name="sampleRate" inputMode="numeric" placeholder="0" />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteTopic.bind(null, arn)} submit="Delete topic" icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm="Delete this topic?" />
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
          rows={subs.map((s) => {
            const waiting = pending(s);
            return {
              key: s.SubscriptionArn! + s.Endpoint,
              icon: protocolIcon(s.Protocol),
              title: waiting ? <Endpoint sub={s} /> : <Endpoint sub={s} linked={false} />,
              href: waiting ? undefined : `/sns/subscription?arn=${encodeURIComponent(s.SubscriptionArn!)}`,
              meta: (
                <>
                  <Pill>{s.Protocol}</Pill>
                  {waiting && <Status tone="warn">pending</Status>}
                </>
              ),
              actions: waiting ? (
                <ActionForm action={confirmPending.bind(null, arn, s.Protocol!, s.Endpoint!)} submit={`Confirm ${s.Endpoint}`} icon={<CheckCheck size={16} aria-hidden />} />
              ) : (
                <ActionForm action={unsubscribe.bind(null, s.SubscriptionArn!)} submit={`Unsubscribe ${s.Endpoint}`} icon={<Unlink size={16} aria-hidden />} tone="danger" />
              ),
            };
          })}
        />
      </Section>
      <Section>
        <Facts
          items={[
            attrs.DisplayName && ["Display name", attrs.DisplayName],
            ["Owner", attrs.Owner],
            ["Encryption", attrs.KmsMasterKeyId ? <Link key="k" href={`/kms/key?id=${encodeURIComponent(attrs.KmsMasterKeyId)}`}>{attrs.KmsMasterKeyId}</Link> : "None"],
            fifo && ["Content-based dedup", attrs.ContentBasedDeduplication === "true" ? "On" : "Off"],
            archiveDays && ["Archive", `${archiveDays} days`],
            attrs.TracingConfig === "Active" && ["Tracing", "Active"],
            attrs.DeliveryPolicy && [
              "Delivery policy",
              <details key="d">
                <summary>custom</summary>
                <CodeBlock value={attrs.DeliveryPolicy} />
              </details>,
            ],
            logging.length > 0 && [
              "Delivery status logging",
              logging.map((p) => (
                <div key={p}>
                  <Pill>{p}</Pill> {[attrs[`${p}SuccessFeedbackRoleArn`], attrs[`${p}FailureFeedbackRoleArn`]].filter(Boolean).map((r) => (arnHref(r) ? <Link key={r} href={arnHref(r)!}>{arnName(r)} </Link> : r))}
                  {attrs[`${p}SuccessFeedbackSampleRate`] && <span className="muted"> {attrs[`${p}SuccessFeedbackSampleRate`]}%</span>}
                </div>
              )),
            ],
          ]}
        />
      </Section>
      {attrs.Policy && (
        <Section title="Access policy">
          <CodeBlock value={attrs.Policy} />
        </Section>
      )}
      <Section
        title="Tags"
        icon={<Tag size={16} aria-hidden />}
        count={tags.length}
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Settings2 size={15} aria-hidden />} testId="topic-tags">
            <ActionForm action={saveTopicTags.bind(null, arn, tagKeys)} submit="Save" testId="topic-tags">
              <Field label="One Key=Value per line" format="tags">
                <textarea name="tags" rows={6} spellCheck={false} defaultValue={tags.map((t) => `${t.Key}=${t.Value}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {tags.length ? <Tags tags={tags} /> : <span className="muted">—</span>}
      </Section>
    </Page>
  );
}
