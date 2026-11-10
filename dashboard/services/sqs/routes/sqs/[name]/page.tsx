import { load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Facts, Field, Metric, Metrics, Page, Section, Sheet } from "@mws-dashboard/ui";
import { Eraser, Send, Settings2, Trash2, Undo2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, isDlq, queues } from "../../../lib/clients";
import { ATTRIBUTE_RULES as RULES, SEND } from "../../../lib/rules";
import { deleteQueue, purgeQueue, receiveMessages, redrive, saveAttributes, sendMessage } from "../actions";

type Props = { params: Promise<{ name: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

const seconds = (s?: string) => {
  const n = Number(s ?? 0);
  return n >= 86400 ? `${+(n / 86400).toFixed(1)}d` : n >= 3600 ? `${+(n / 3600).toFixed(1)}h` : n >= 60 ? `${+(n / 60).toFixed(1)}m` : `${n}s`;
};

export default async function Queue({ params }: Props) {
  const name = decodeURIComponent((await params).name);
  const all = await load(queues);
  const queue = all.ok ? all.value.find((q) => q.name === name) : undefined;
  const back = { href: "/sqs", label: "Queues" };
  if (!queue) {
    return (
      <Page title={name} back={back}>
        <ErrorNotice error={all.ok ? "The queue does not exist." : all.error} />
      </Page>
    );
  }
  const { attrs } = queue;
  const fifo = attrs.FifoQueue === "true";
  const dlq = isDlq(queue);
  const visible = Number(attrs.ApproximateNumberOfMessages ?? 0);
  return (
    <Page
      title={name}
      icon={ICONS.queue}
      back={back}
      subtitle={queue.url}
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
            </ActionForm>
          </Sheet>
          {dlq && visible > 0 && (
            <ActionForm
              action={redrive.bind(null, queue.arn)}
              submit="Redrive to source"
              icon={<Undo2 size={16} aria-hidden />}
              confirm="Move these messages back to their source queues?"
            />
          )}
          <Sheet title="Configuration" label="Edit configuration" icon={<Settings2 size={15} aria-hidden />} testId="queue-config">
            <ActionForm action={saveAttributes.bind(null, name)} submit="Save" testId="queue-config">
              <div className="form-row">
                <Field label="Visibility timeout (s)" rule={RULES.VisibilityTimeout}>
                  <input name="VisibilityTimeout" inputMode="numeric" defaultValue={attrs.VisibilityTimeout} />
                </Field>
                <Field label="Retention (s)" rule={RULES.MessageRetentionPeriod}>
                  <input name="MessageRetentionPeriod" inputMode="numeric" defaultValue={attrs.MessageRetentionPeriod} />
                </Field>
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
              <Field label="Access policy" rule={RULES.Policy}>
                <textarea name="Policy" rows={8} defaultValue={attrs.Policy ? JSON.stringify(JSON.parse(attrs.Policy), null, 2) : ""} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={purgeQueue.bind(null, name)}
            submit="Purge"
            icon={<Eraser size={16} aria-hidden />}
            tone="danger"
            confirm={`Delete every message in ${name}?`}
          />
          <ActionForm
            action={deleteQueue.bind(null, name)}
            submit="Delete queue"
            icon={<Trash2 size={16} aria-hidden />}
            tone="danger"
            confirm={`Delete queue ${name}?`}
          />
        </>
      }
    >
      <Metrics>
        <Metric label="Available" value={<span data-testid="available">{visible}</span>} tone={dlq && visible > 0 ? "bad" : undefined} />
        <Metric label="In flight" value={attrs.ApproximateNumberOfMessagesNotVisible ?? "0"} />
        <Metric label="Delayed" value={attrs.ApproximateNumberOfMessagesDelayed ?? "0"} />
      </Metrics>
      <Section title="Messages">
        <ActionForm action={receiveMessages.bind(null, name)} submit="Poll" inline testId="receive-messages">
          <select name="mode" defaultValue="peek" aria-label="Mode">
            <option value="peek">Peek</option>
            <option value="delete">Receive and delete</option>
          </select>
        </ActionForm>
      </Section>
      <Section title="Configuration">
        <Facts
          items={[
            ["ARN", <code>{queue.arn}</code>],
            ["Visibility timeout", seconds(attrs.VisibilityTimeout)],
            ["Retention", seconds(attrs.MessageRetentionPeriod)],
            Number(attrs.DelaySeconds) > 0 && ["Delay", seconds(attrs.DelaySeconds)],
            Number(attrs.ReceiveMessageWaitTimeSeconds) > 0 && ["Long polling", seconds(attrs.ReceiveMessageWaitTimeSeconds)],
            ["Encryption", attrs.KmsMasterKeyId ?? (attrs.SqsManagedSseEnabled === "true" ? "SSE-SQS" : "None")],
            queue.dlq && ["Dead-letter queue", <Link href={`/sqs/${encodeURIComponent(queue.dlq)}`}>{queue.dlq}</Link>],
            queue.sources.length > 0 && [
              "Dead letters from",
              queue.sources.map((s) => (
                <div key={s}>
                  <Link href={`/sqs/${encodeURIComponent(s)}`}>{s}</Link>
                </div>
              )),
            ],
          ]}
        />
      </Section>
      {attrs.Policy && (
        <Section title="Access policy">
          <CodeBlock value={attrs.Policy} label="Access policy" />
        </Section>
      )}
    </Page>
  );
}
