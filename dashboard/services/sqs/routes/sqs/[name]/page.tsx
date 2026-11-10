import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, CopyValue, Empty, ErrorNotice, Facts, Field, List, Metric, Metrics, Page, Pill, Section, Sheet, Status, Tags, type Tone } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { Eraser, Inbox, OctagonX, Plane, Send, Settings2, Tag, Timer, Trash2, Undo2, Zap } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { functionArns, ICONS, neighbours, queue, queues } from "../../../lib/clients";
import { arnHref, arnName, parseArn } from "../../../lib/links";
import { Messages } from "../../../lib/messages";
import { ATTRIBUTE_RULES as RULES, BATCH_SIZE, COPIES, KMS_KEY, KMS_REUSE, MAX_RECEIVES, MESSAGE_ATTRIBUTES, MOVE_RATE, SEND, SOURCE_ARNS } from "../../../lib/rules";
import { QueueSettings, type Current } from "../../../lib/settings";
import {
  addLambdaTrigger,
  cancelRedrive,
  deleteMessage,
  deleteQueue,
  purgeQueue,
  receiveMessages,
  redrive,
  releaseMessage,
  saveAttributes,
  saveTags,
  sendMessage,
} from "../actions";
import { PolicyEditor } from "@mws-dashboard/ui/policy";

type Props = { params: Promise<{ name: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

const seconds = (s?: string) => {
  const n = Number(s ?? 0);
  return n >= 86400 ? `${+(n / 86400).toFixed(1)}d` : n >= 3600 ? `${+(n / 3600).toFixed(1)}h` : n >= 60 ? `${+(n / 60).toFixed(1)}m` : `${n}s`;
};

const TASK_TONE: Record<string, Tone> = { RUNNING: "info", COMPLETED: "good", FAILED: "bad", CANCELLING: "info", CANCELLED: "neutral" };

export default async function Queue({ params }: Props) {
  const name = decodeURIComponent((await params).name);
  const back = { href: "/sqs", label: "Queues" };
  const data = await load(() => queue(name));
  if (!data.ok) {
    return (
      <Page title={name} back={back}>
        <ErrorNotice error={/NonExistentQueue|QueueDoesNotExist/.test(data.error) ? "The queue does not exist." : data.error} />
      </Page>
    );
  }
  const q = data.value;
  const { attrs } = q;
  const [others, near, fns] = await Promise.all([queues().catch(() => []), neighbours(q.arn), functionArns().catch(() => [])]);
  const fifo = attrs.FifoQueue === "true";
  const isDlq = q.sources.length > 0;
  const visible = Number(attrs.ApproximateNumberOfMessages ?? 0);
  const inflight = Number(attrs.ApproximateNumberOfMessagesNotVisible ?? 0);
  const delayed = Number(attrs.ApproximateNumberOfMessagesDelayed ?? 0);
  const running = q.tasks.some((t) => t.Status === "RUNNING" || t.Status === "CANCELLING");
  const me = parseArn(q.arn);
  const local = (arn: string) => {
    const a = parseArn(arn);
    return a && me && a.account === me.account && a.region === me.region;
  };
  const queueLink = (arn: string) => (local(arn) ? <Link href={arnHref(arn)!}>{arnName(arn)}</Link> : <code>{arn}</code>);
  let allow: { redrivePermission?: string; sourceQueueArns?: string[] } = {};
  try {
    allow = attrs.RedriveAllowPolicy ? JSON.parse(attrs.RedriveAllowPolicy) : {};
  } catch {
    // malformed
  }
  const encryption: Current["encryption"] = attrs.KmsMasterKeyId ? "kms" : attrs.SqsManagedSseEnabled === "true" ? "sqs" : "none";
  const current: Current = {
    dlq: q.dlq?.arn,
    maxReceiveCount: q.dlq?.maxReceiveCount,
    allow: allow.redrivePermission,
    allowSources: allow.sourceQueueArns,
    encryption,
    kmsKey: attrs.KmsMasterKeyId,
    kmsReuse: attrs.KmsDataKeyReusePeriodSeconds,
    dedup: attrs.ContentBasedDeduplication === "true",
    dedupScope: attrs.DeduplicationScope,
    throughput: attrs.FifoThroughputLimit,
  };
  const candidates = others.filter((o) => o.arn !== q.arn).map((o) => ({ name: o.name, arn: o.arn, fifo: o.attrs.FifoQueue === "true" }));
  const settingRules = { maxReceives: MAX_RECEIVES, kmsKey: KMS_KEY, kmsReuse: KMS_REUSE, sources: SOURCE_ARNS };
  const tags = q.tags as Record<string, string>;
  return (
    <Page
      title={name}
      icon={ICONS.queue}
      back={back}
      subtitle={q.url}
      actions={
        <>
          <Sheet title="Send message" label="Send message" icon={<Send size={15} aria-hidden />} testId="send-message">
            <ActionForm action={sendMessage.bind(null, name)} submit="Send" testId="send-message">
              <Field label="Body" rule={SEND.MessageBody}>
                <textarea name="body" required maxLength={Number(attrs.MaximumMessageSize) || undefined} autoFocus />
              </Field>
              <div className="form-row">
                {fifo ? (
                  <>
                    <Field label="Group ID" rule={SEND.MessageGroupId}>
                      <input name="group" required defaultValue="default" />
                    </Field>
                    {attrs.ContentBasedDeduplication !== "true" && (
                      <Field label="Deduplication ID" rule={SEND.MessageDeduplicationId}>
                        <input name="dedup" required />
                      </Field>
                    )}
                  </>
                ) : (
                  <Field label="Delay (s)" rule={SEND.DelaySeconds}>
                    <input name="delay" inputMode="numeric" />
                  </Field>
                )}
              </div>
              <Field label="Message attributes" rule={MESSAGE_ATTRIBUTES} member="MessageAttributes">
                <textarea name="attributes" rows={2} placeholder={"type=order\npriority:Number=1"} spellCheck={false} />
              </Field>
              <MoreFields>
                <div className="form-row">
                  <Field label="Copies" rule={COPIES}>
                    <input name="copies" inputMode="numeric" placeholder="1" />
                  </Field>
                  <Field label="X-Ray trace header">
                    <input name="trace" placeholder="Root=1-…" spellCheck={false} />
                  </Field>
                </div>
              </MoreFields>
            </ActionForm>
          </Sheet>
          <Sheet title="Configuration" label="Edit configuration" icon={<Settings2 size={15} aria-hidden />} testId="queue-config">
            <ActionForm action={saveAttributes.bind(null, name, fifo)} submit="Save" testId="queue-config">
              <div className="form-row">
                <Field label="Visibility timeout (s)" rule={RULES.VisibilityTimeout}>
                  <input name="VisibilityTimeout" inputMode="numeric" defaultValue={attrs.VisibilityTimeout} />
                </Field>
                <Field label="Retention (s)" rule={RULES.MessageRetentionPeriod}>
                  <input name="MessageRetentionPeriod" inputMode="numeric" defaultValue={attrs.MessageRetentionPeriod} />
                </Field>
              </div>
              <MoreFields label="Delay, long polling, size">
                <div className="form-row">
                  <Field label="Delay (s)" rule={RULES.DelaySeconds}>
                    <input name="DelaySeconds" inputMode="numeric" defaultValue={attrs.DelaySeconds} />
                  </Field>
                  <Field label="Receive wait (s)" rule={RULES.ReceiveMessageWaitTimeSeconds}>
                    <input name="ReceiveMessageWaitTimeSeconds" inputMode="numeric" defaultValue={attrs.ReceiveMessageWaitTimeSeconds} />
                  </Field>
                  <Field label="Max size (bytes)" rule={RULES.MaximumMessageSize}>
                    <input name="MaximumMessageSize" inputMode="numeric" defaultValue={attrs.MaximumMessageSize} />
                  </Field>
                </div>
              </MoreFields>
              <QueueSettings queues={candidates} current={current} fifo={fifo} rules={settingRules} />
              <PolicyEditor label="Access policy" rule={RULES.Policy} kind="resource" name="Policy" rows={8} defaultValue={attrs.Policy ? JSON.stringify(JSON.parse(attrs.Policy), null, 2) : ""} />
            </ActionForm>
          </Sheet>
          <Sheet title="Lambda trigger" label="Configure Lambda function trigger" icon={<Zap size={15} aria-hidden />} testId="lambda-trigger">
            <ActionForm action={addLambdaTrigger.bind(null, name, q.arn)} submit="Save" testId="lambda-trigger">
              <div className="form-row">
                <Field label="Function">
                  <select name="function" required>
                    {fns.map((f) => (
                      <option key={f.arn} value={f.arn}>
                        {f.name}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Batch size" rule={BATCH_SIZE}>
                  <input name="batch" inputMode="numeric" placeholder="10" />
                </Field>
              </div>
              <label className="check">
                <input type="checkbox" name="grant" defaultChecked /> Add the queue permissions to the function&apos;s role
              </label>
            </ActionForm>
          </Sheet>
          <ActionForm action={purgeQueue.bind(null, name)} submit="Purge" icon={<Eraser size={16} aria-hidden />} tone="danger" confirm={`Delete every message in ${name}?`} />
          <ActionForm action={deleteQueue.bind(null, name)} submit="Delete queue" icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm={`Delete queue ${name}?`} />
        </>
      }
    >
      <LiveRefresh when={running || inflight > 0 || delayed > 0} />
      <Metrics>
        <Metric label="Available" icon={<Inbox size={14} aria-hidden />} value={<span data-testid="available">{visible}</span>} tone={isDlq && visible > 0 ? "bad" : undefined} />
        <Metric label="In flight" icon={<Plane size={14} aria-hidden />} value={inflight} />
        <Metric label="Delayed" icon={<Timer size={14} aria-hidden />} value={delayed} />
      </Metrics>
      {isDlq && (
        <Section
          title="Dead-letter queue redrive"
          icon={<Undo2 size={16} aria-hidden />}
          actions={
            visible > 0 && !running ? (
              <Sheet title="Start DLQ redrive" label="Start DLQ redrive" icon={<Undo2 size={15} aria-hidden />} testId="redrive">
                <ActionForm action={redrive.bind(null, name, q.arn)} submit="Redrive" testId="redrive">
                  <Field label="Destination" hint="Empty: back to each message's source queue" format="arn" known={candidates.map((c) => c.arn)}>
                    <input name="destination" spellCheck={false} />
                  </Field>
                  <Field label="Velocity (messages/s)" rule={MOVE_RATE}>
                    <input name="rate" inputMode="numeric" />
                  </Field>
                </ActionForm>
              </Sheet>
            ) : undefined
          }
        >
          <List
            label="Redrive tasks"
            empty={<span className="muted">—</span>}
            rows={q.tasks.map((t) => ({
              key: t.TaskHandle ?? String(t.StartedTimestamp),
              icon: <Undo2 size={18} aria-hidden />,
              title: t.DestinationArn ? queueLink(t.DestinationArn) : "Source queues",
              subtitle: t.FailureReason ? <span className="tone-bad">{t.FailureReason}</span> : undefined,
              meta: (
                <>
                  <span title="Moved">
                    {t.ApproximateNumberOfMessagesMoved ?? 0}
                    {t.ApproximateNumberOfMessagesToMove !== undefined ? ` / ${t.ApproximateNumberOfMessagesToMove}` : ""} moved
                  </span>
                  {t.MaxNumberOfMessagesPerSecond && <Pill>{t.MaxNumberOfMessagesPerSecond}/s</Pill>}
                  <span>{ago(t.StartedTimestamp)}</span>
                  <Status tone={TASK_TONE[t.Status ?? ""] ?? "neutral"}>{t.Status ?? ""}</Status>
                </>
              ),
              actions:
                t.Status === "RUNNING" && t.TaskHandle ? (
                  <ActionForm action={cancelRedrive.bind(null, name, t.TaskHandle)} submit="Cancel redrive" icon={<OctagonX size={15} aria-hidden />} tone="danger" confirm="Stop moving messages?" />
                ) : undefined,
            }))}
          />
        </Section>
      )}
      <Section title="Messages">
        <Messages poll={receiveMessages.bind(null, name)} remove={deleteMessage.bind(null, name)} release={releaseMessage.bind(null, name)} maxReceives={q.dlq?.maxReceiveCount} />
      </Section>
      <Section title="Configuration">
        <Facts
          items={[
            ["ARN", <CopyValue key="a" value={q.arn} label="Copy ARN" />],
            fifo && ["Type", <Pill key="f" tone="info">FIFO</Pill>],
            ["Visibility timeout", seconds(attrs.VisibilityTimeout)],
            ["Retention", seconds(attrs.MessageRetentionPeriod)],
            Number(attrs.DelaySeconds) > 0 && ["Delay", seconds(attrs.DelaySeconds)],
            Number(attrs.ReceiveMessageWaitTimeSeconds) > 0 && ["Long polling", seconds(attrs.ReceiveMessageWaitTimeSeconds)],
            [
              "Encryption",
              encryption === "kms" ? (
                <Link key="k" href={`/kms/key?id=${encodeURIComponent(attrs.KmsMasterKeyId!)}`}>{attrs.KmsMasterKeyId}</Link>
              ) : encryption === "sqs" ? (
                "SSE-SQS"
              ) : (
                <Pill key="n" tone="warn">None</Pill>
              ),
            ],
            fifo && ["Content-based deduplication", attrs.ContentBasedDeduplication === "true" ? "On" : "Off"],
            fifo && attrs.DeduplicationScope && ["Deduplication scope", attrs.DeduplicationScope],
            fifo && attrs.FifoThroughputLimit && ["Throughput limit", attrs.FifoThroughputLimit],
            q.dlq && ["Dead-letter queue", <span key="d">{queueLink(q.dlq.arn)} after {q.dlq.maxReceiveCount} receives</span>],
            q.sources.length > 0 && [
              "Dead letters from",
              q.sources.map((s) => <div key={s}>{queueLink(s)}</div>),
            ],
            allow.redrivePermission && [
              "Redrive allow policy",
              allow.redrivePermission === "byQueue" ? (allow.sourceQueueArns ?? []).map((s) => <div key={s}>{queueLink(s)}</div>) : allow.redrivePermission,
            ],
          ]}
        />
      </Section>
      <Section title="Consumers and producers" count={near.mappings.length + near.subscriptions.length + near.rules.length} plain>
        <List
          label="Consumers and producers"
          empty={<Empty icon={ICONS.queue} />}
          rows={[
            ...near.mappings.map((m) => ({
              key: m.UUID!,
              icon: <AwsIcon icon="resource/AWSLambdaLambdaFunction" size={22} />,
              title: <Link href={`/lambda/${encodeURIComponent(arnName(m.FunctionArn).split(":")[0])}?tab=triggers`}>{arnName(m.FunctionArn)}</Link>,
              subtitle: m.LastProcessingResult,
              meta: (
                <>
                  {m.BatchSize && <Pill title="Batch size">×{m.BatchSize}</Pill>}
                  <Status tone={m.State === "Enabled" ? "good" : "neutral"}>{m.State ?? ""}</Status>
                </>
              ),
            })),
            ...near.subscriptions.map((s) => ({
              key: s.SubscriptionArn!,
              icon: <AwsIcon icon="resource/AmazonSimpleNotificationServiceTopic" size={22} />,
              title: <Link href={`/sns/topic?arn=${encodeURIComponent(s.TopicArn!)}`}>{arnName(s.TopicArn)}</Link>,
              meta: s.SubscriptionArn === "PendingConfirmation" ? <Status tone="warn">pending</Status> : <Pill>subscription</Pill>,
            })),
            ...near.rules.map((r) => ({
              key: `${r.bus}/${r.rule}`,
              icon: <AwsIcon icon="resource/AmazonEventBridgeRule" size={22} />,
              title: <Link href={`/events/rule?bus=${encodeURIComponent(r.bus)}&name=${encodeURIComponent(r.rule)}`}>{r.rule}</Link>,
              meta: r.bus !== "default" ? <Pill>{r.bus}</Pill> : <Pill>rule</Pill>,
            })),
          ]}
        />
      </Section>
      {attrs.Policy && (
        <Section title="Access policy">
          <CodeBlock value={attrs.Policy} label="Access policy" />
        </Section>
      )}
      <Section
        title="Tags"
        icon={<Tag size={16} aria-hidden />}
        count={Object.keys(tags).length}
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Settings2 size={15} aria-hidden />} testId="queue-tags">
            <ActionForm action={saveTags.bind(null, name, Object.keys(tags))} submit="Save" testId="queue-tags">
              <Field label="One Key=Value per line" format="tags">
                <textarea name="tags" rows={6} spellCheck={false} defaultValue={Object.entries(tags).map(([k, v]) => `${k}=${v}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {Object.keys(tags).length ? <Tags tags={tags} /> : <span className="muted">—</span>}
      </Section>
    </Page>
  );
}
