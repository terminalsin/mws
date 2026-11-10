import { DescribeLogGroupsCommand, DescribeLogStreamsCommand, FilterLogEventsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { ago, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { FilterLogEvents, PutLogEvents, PutRetentionPolicy } from "@mws-dashboard/ui/model/logs";
import { Clock, PenLine, Trash2, X } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, groupHref, logs, sourceIcon } from "../../../lib/clients";
import { RETENTION, retentionLabel } from "../../../lib/retention";
import { deleteGroup, setRetention, writeEvent } from "../actions";

type Props = { searchParams: Promise<{ name?: string; stream?: string; pattern?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: (await searchParams).name ?? "Log group" };
}

const LEVEL = /\b(ERROR|FATAL|CRITICAL|Exception|Traceback|WARN(ING)?)\b/;

export default async function LogGroup({ searchParams }: Props) {
  const { name = "", stream, pattern } = await searchParams;
  const back = { href: "/logs", label: "Log groups" };
  const client = await logs();
  const [group, streams, events] = await Promise.all([
    load(async () => (await client.send(new DescribeLogGroupsCommand({ logGroupNamePrefix: name }))).logGroups?.find((g) => g.logGroupName === name)),
    load(async () => (await client.send(new DescribeLogStreamsCommand({ logGroupName: name, orderBy: "LastEventTime", descending: true, limit: 50 }))).logStreams ?? []),
    load(async () => {
      const out = await client.send(
        new FilterLogEventsCommand({
          logGroupName: name,
          limit: 500,
          ...(stream ? { logStreamNames: [stream] } : {}),
          ...(pattern ? { filterPattern: pattern } : {}),
        }),
      );
      return (out.events ?? []).sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0));
    }),
  ]);
  const g = group.ok ? group.value : undefined;
  const streamNames = streams.ok ? streams.value.map((s) => s.logStreamName!) : [];
  const icon = sourceIcon(name) ?? ICONS.logs;
  return (
    <Page
      title={name}
      icon={icon}
      back={back}
      actions={
        <>
          <Sheet title="Write event" label="Write event" icon={<PenLine size={16} />} testId="write-event">
            <ActionForm action={writeEvent.bind(null, name)} submit="Write" testId="write-event">
              <Field label="Stream" rule={PutLogEvents.logStreamName} known={streamNames} generate="name">
                <input name="stream" defaultValue={stream ?? "console"} />
              </Field>
              <Field label="Message" rule={PutLogEvents.logEvents.item!.fields!.message}>
                <textarea name="message" rows={3} />
              </Field>
            </ActionForm>
          </Sheet>
          <Sheet title="Retention" label="Change retention" icon={<Clock size={16} />} testId="retention">
            <ActionForm action={setRetention.bind(null, name)} submit="Save" testId="retention">
              <Field label="Retention" rule={PutRetentionPolicy.retentionInDays}>
                <select name="retention" defaultValue={g?.retentionInDays ?? 0}>
                  {RETENTION.map((d) => (
                    <option key={d} value={d}>
                      {retentionLabel(d)}
                    </option>
                  ))}
                </select>
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteGroup.bind(null, name)} submit="Delete log group" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name} and all its events?`} testId="delete-log-group" />
        </>
      }
    >
      {g && (
        <Facts
          items={[
            ["Retention", retentionLabel(g.retentionInDays ?? 0)],
            ["Stored", bytes(g.storedBytes ?? 0)],
            g.metricFilterCount ? ["Metric filters", g.metricFilterCount] : null,
            g.kmsKeyId && ["KMS key", g.kmsKeyId.split("/").pop()],
            g.dataProtectionStatus && ["Data protection", g.dataProtectionStatus],
            ["Created", ago(g.creationTime)],
          ]}
        />
      )}
      <form className="search-page-form" action="/logs/group">
        <input type="hidden" name="name" value={name} />
        {stream && <input type="hidden" name="stream" value={stream} />}
        <Field label="Filter pattern" rule={FilterLogEvents.filterPattern}>
          <input name="pattern" defaultValue={pattern} placeholder='ERROR or { $.level = "warn" }' aria-label="Filter pattern" />
        </Field>
      </form>
      {stream && (
        <div className="chips">
          <span className="chip">
            {stream}
            <Link className="icon-button plain" href={groupHref(name, pattern ? { pattern } : {})} aria-label="All streams">
              <X size={11} />
            </Link>
          </span>
        </div>
      )}
      <Section plain>
        {events.ok ? (
          events.value.length ? (
            <ol className="log-events" aria-label="Log events">
              {events.value.map((e) => {
                const level = e.message?.match(LEVEL)?.[1];
                return (
                  <li key={e.eventId ?? `${e.logStreamName}-${e.timestamp}-${e.message}`} className={level ? (level.startsWith("WARN") ? "warn" : "bad") : undefined}>
                    <time dateTime={new Date(e.timestamp ?? 0).toISOString()} title={new Date(e.timestamp ?? 0).toISOString()}>
                      {new Date(e.timestamp ?? 0).toISOString().slice(11, 23)}
                    </time>
                    <pre>{e.message}</pre>
                    {!stream && streams.ok && streams.value.length > 1 && (
                      <Link className="log-stream" href={groupHref(name, { stream: e.logStreamName! })}>
                        {e.logStreamName}
                      </Link>
                    )}
                  </li>
                );
              })}
            </ol>
          ) : (
            <Empty icon={icon} />
          )
        ) : (
          <ErrorNotice error={events.error} />
        )}
      </Section>
      {!stream && streams.ok && streams.value.length > 1 && (
        <Section title="Streams" count={streams.value.length} plain>
          <List
            label="Log streams"
            rows={streams.value.map((s) => ({
              key: s.logStreamName!,
              icon: <AwsIcon icon={ICONS.logs} size={18} />,
              title: s.logStreamName,
              href: groupHref(name, { stream: s.logStreamName! }),
              meta: <Pill>{ago(s.lastEventTimestamp ?? s.creationTime)}</Pill>,
            }))}
          />
        </Section>
      )}
    </Page>
  );
}
