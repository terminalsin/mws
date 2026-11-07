import { GetQueueAttributesCommand, GetQueueUrlCommand } from "@aws-sdk/client-sqs";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Field, KeyValue, PageHeader, Section, Stat, Grid } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { sqs } from "../../../lib/clients";
import { deleteQueue, purgeQueue, receiveMessages, sendMessage } from "../actions";

type Props = { params: Promise<{ name: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).name) };
}

export default async function Queue({ params }: Props) {
  const name = decodeURIComponent((await params).name);
  const queue = await load(async () => {
    const client = await sqs();
    const url = (await client.send(new GetQueueUrlCommand({ QueueName: name }))).QueueUrl!;
    const attrs = (await client.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ["All"] }))).Attributes ?? {};
    return { url, attrs };
  });
  const crumbs = [{ label: "SQS queues", href: "/sqs" }];
  if (!queue.ok) {
    return (
      <>
        <PageHeader title={name} crumbs={crumbs} />
        <ErrorNotice error={queue.error} />
      </>
    );
  }
  const { url, attrs } = queue.value;
  const fifo = attrs.FifoQueue === "true";
  return (
    <>
      <PageHeader title={name} crumbs={crumbs} description={<code>{url}</code>} />
      <Grid>
        <Stat label="Available" value={<span data-testid="available">{attrs.ApproximateNumberOfMessages ?? "0"}</span>} />
        <Stat label="In flight" value={attrs.ApproximateNumberOfMessagesNotVisible ?? "0"} />
        <Stat label="Delayed" value={attrs.ApproximateNumberOfMessagesDelayed ?? "0"} />
      </Grid>
      <Section title="Send a message">
        <ActionForm action={sendMessage.bind(null, name)} submit="Send" testId="send-message">
          <Field label="Body">
            <textarea name="body" required />
          </Field>
          <div className="form-row">
            {fifo && (
              <>
                <Field label="Message group ID">
                  <input name="group" required defaultValue="default" />
                </Field>
                {attrs.ContentBasedDeduplication !== "true" && (
                  <Field label="Deduplication ID">
                    <input name="dedup" required />
                  </Field>
                )}
              </>
            )}
            {!fifo && (
              <Field label="Delay (seconds)">
                <input name="delay" type="number" min="0" max="900" />
              </Field>
            )}
          </div>
        </ActionForm>
      </Section>
      <Section title="Receive messages">
        <ActionForm action={receiveMessages.bind(null, name)} submit="Receive" inline testId="receive-messages">
          <Field label="Mode">
            <select name="mode" defaultValue="peek">
              <option value="peek">Peek (leave them on the queue)</option>
              <option value="delete">Receive and delete</option>
            </select>
          </Field>
        </ActionForm>
      </Section>
      <Section title="Attributes">
        <KeyValue
          items={[
            ["ARN", <code>{attrs.QueueArn}</code>],
            ["Visibility timeout", `${attrs.VisibilityTimeout}s`],
            ["Retention", `${attrs.MessageRetentionPeriod}s`],
            ["Max message size", `${attrs.MaximumMessageSize} B`],
            ["Receive wait", `${attrs.ReceiveMessageWaitTimeSeconds}s`],
            ["Delay", `${attrs.DelaySeconds}s`],
            ["Encryption", attrs.KmsMasterKeyId ?? (attrs.SqsManagedSseEnabled === "true" ? "SSE-SQS" : "none")],
            ["Created", when(Number(attrs.CreatedTimestamp) * 1000)],
            ["Last modified", when(Number(attrs.LastModifiedTimestamp) * 1000)],
          ]}
        />
        {attrs.RedrivePolicy && (
          <>
            <h2 style={{ margin: "16px 0 8px" }}>Redrive policy</h2>
            <CodeBlock value={attrs.RedrivePolicy} />
          </>
        )}
        {attrs.Policy && (
          <>
            <h2 style={{ margin: "16px 0 8px" }}>Access policy</h2>
            <CodeBlock value={attrs.Policy} />
          </>
        )}
      </Section>
      <Section title="Danger zone">
        <div className="form-row">
          <ActionForm action={purgeQueue.bind(null, name)} submit="Purge messages" tone="danger" confirm={`Purge every message in ${name}?`} inline />
          <ActionForm action={deleteQueue.bind(null, name)} submit="Delete queue" tone="danger" confirm={`Delete queue ${name}?`} inline />
        </div>
      </Section>
    </>
  );
}
