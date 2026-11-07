import { DescribeLogStreamsCommand, FilterLogEventsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Field, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { groupHref, logs } from "../../../lib/clients";
import { deleteGroup, writeEvent } from "../actions";

type Props = { searchParams: Promise<{ name?: string; stream?: string; pattern?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: (await searchParams).name ?? "Log group" };
}

export default async function LogGroup({ searchParams }: Props) {
  const { name = "", stream, pattern } = await searchParams;
  const client = await logs();
  const [streams, events] = await Promise.all([
    load(async () =>
      (
        await client.send(new DescribeLogStreamsCommand({ logGroupName: name, orderBy: "LastEventTime", descending: true, limit: 50 }))
      ).logStreams ?? [],
    ),
    load(async () => {
      const out = await client.send(
        new FilterLogEventsCommand({
          logGroupName: name,
          limit: 200,
          ...(stream ? { logStreamNames: [stream] } : {}),
          ...(pattern ? { filterPattern: pattern } : {}),
        }),
      );
      return out.events ?? [];
    }),
  ]);
  const crumbs = [{ label: "Log groups", href: "/logs" }];
  return (
    <>
      <PageHeader title={name} crumbs={crumbs} />
      <Section
        title={stream ? `Events in ${stream}` : "Events in all streams"}
        actions={
          <form className="form-row" action="/observability/logs/group">
            <input type="hidden" name="name" value={name} />
            {stream && <input type="hidden" name="stream" value={stream} />}
            <input name="pattern" defaultValue={pattern} placeholder='Filter pattern, e.g. ERROR or { $.level = "warn" }' size={40} aria-label="Filter pattern" />
            <button className="button primary" type="submit">
              Search
            </button>
          </form>
        }
      >
        {events.ok ? (
          <Table
            label="Log events"
            rows={events.value}
            rowKey={(e) => e.eventId ?? `${e.logStreamName}-${e.timestamp}-${e.message}`}
            empty={pattern ? "No events match the pattern." : "No events yet."}
            columns={[
              { header: "Time", cell: (e) => when(e.timestamp) },
              ...(stream ? [] : [{ header: "Stream", className: "wrap", cell: (e: { logStreamName?: string }) => <code>{e.logStreamName}</code> }]),
              { header: "Message", className: "wrap", cell: (e) => <pre className="code">{e.message}</pre> },
            ]}
          />
        ) : (
          <ErrorNotice error={events.error} />
        )}
        {stream && (
          <p>
            <Link href={groupHref(name)}>Show all streams</Link>
          </p>
        )}
      </Section>
      <Section title="Streams">
        {streams.ok ? (
          <Table
            label="Log streams"
            rows={streams.value}
            rowKey={(s) => s.logStreamName!}
            empty="No streams."
            columns={[
              { header: "Stream", className: "wrap", cell: (s) => <Link href={groupHref(name, { stream: s.logStreamName! })}>{s.logStreamName}</Link> },
              { header: "Last event", cell: (s) => when(s.lastEventTimestamp) },
              { header: "Created", cell: (s) => when(s.creationTime) },
            ]}
          />
        ) : (
          <ErrorNotice error={streams.error} />
        )}
      </Section>
      <Section title="Write an event">
        <ActionForm action={writeEvent.bind(null, name)} submit="Put log event" inline testId="write-event">
          <Field label="Stream">
            <input name="stream" defaultValue={stream ?? "console"} />
          </Field>
          <Field label="Message">
            <input name="message" required size={48} />
          </Field>
        </ActionForm>
      </Section>
      <Section title="Delete">
        <ActionForm action={deleteGroup.bind(null, name)} submit="Delete log group" tone="danger" confirm={`Delete ${name} and all its events?`} inline />
      </Section>
    </>
  );
}
