import {
  DescribeQueriesCommand,
  DescribeQueryDefinitionsCommand,
  GetLogGroupFieldsCommand,
  GetQueryResultsCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { ago, all, bytes, load } from "@mws-dashboard/aws";
import {
  ActionForm,
  Empty,
  ErrorNotice,
  Field,
  List,
  Metric,
  Metrics,
  Page,
  Pill,
  Section,
  Sheet,
  Status,
  Table,
} from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { PutQueryDefinition, StartQuery } from "@mws-dashboard/ui/model/logs";
import { Bookmark, CircleStop, FileSearch, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, listGroups, logs } from "../../../lib/clients";
import { deleteQuery, saveQuery, startQuery, stopQuery } from "../actions";

export const metadata: Metadata = { title: "Logs Insights" };

type Props = {
  searchParams: Promise<{
    id?: string;
    q?: string;
    groups?: string;
    minutes?: string;
    language?: string;
  }>;
};

const DEFAULT =
  "fields @timestamp, @message, @logStream\n| sort @timestamp desc\n| limit 20";
const RANGES: [number, string][] = [
  [5, "5 min"],
  [15, "15 min"],
  [60, "1 hour"],
  [180, "3 hours"],
  [720, "12 hours"],
  [1440, "1 day"],
  [10080, "1 week"],
];
const LANGUAGES: [string, string][] = [
  ["CWLI", "Logs Insights QL"],
  ["SQL", "OpenSearch SQL"],
  ["PPL", "OpenSearch PPL"],
];
const STATE_TONE: Record<string, "good" | "bad" | "warn" | "neutral"> = {
  Complete: "good",
  Failed: "bad",
  Timeout: "bad",
  Cancelled: "neutral",
  Running: "warn",
  Scheduled: "warn",
  Unknown: "neutral",
};

const href = (p: Record<string, string | undefined>) =>
  `/logs/insights?${new URLSearchParams(Object.entries(p).filter((e): e is [string, string] => !!e[1]))}`;

async function Results({ id }: { id: string }) {
  const res = await load(async () =>
    (await logs()).send(new GetQueryResultsCommand({ queryId: id })),
  );
  if (!res.ok) return <ErrorNotice error={res.error} />;
  const { status = "Unknown", results = [], statistics } = res.value;
  const running = status === "Running" || status === "Scheduled";
  const columns = [
    ...new Set(results.flatMap((r) => r.map((f) => f.field!))),
  ].filter((f) => f !== "@ptr");
  const rows = results.map((r, i) => ({
    i,
    cells: Object.fromEntries(r.map((f) => [f.field!, f.value ?? ""])),
  }));
  return (
    <Section
      title={<Status tone={STATE_TONE[status] ?? "neutral"}>{status}</Status>}
      count={results.length}
      actions={
        running ? (
          <ActionForm
            action={stopQuery.bind(null, id)}
            submit="Stop query"
            icon={<CircleStop size={15} />}
            tone="danger"
          />
        ) : undefined
      }
      plain
    >
      <LiveRefresh when={running} every={1000} />
      {statistics && (
        <Metrics>
          <Metric
            label="Records matched"
            value={statistics.recordsMatched ?? 0}
          />
          <Metric
            label="Records scanned"
            value={statistics.recordsScanned ?? 0}
          />
          <Metric label="Scanned" value={bytes(statistics.bytesScanned ?? 0)} />
        </Metrics>
      )}
      <Table
        label="Query results"
        rows={rows}
        rowKey={(r) => String(r.i)}
        empty={running ? undefined : <Empty icon={ICONS.logs} />}
        columns={columns.map((c) => ({
          header: c,
          cell: (r: (typeof rows)[number]) =>
            c === "@message" ? (
              <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                {r.cells[c]}
              </pre>
            ) : (
              (r.cells[c] ?? "")
            ),
          className: c === "@message" ? undefined : "nowrap",
        }))}
      />
    </Section>
  );
}

export default async function Insights({ searchParams }: Props) {
  const {
    id: query,
    q,
    groups: groupParam,
    minutes = "60",
    language = "CWLI",
  } = await searchParams;
  const selected = (groupParam ?? "").split(",").filter(Boolean);
  const client = await logs();
  const [groups, saved, recent, fields] = await Promise.all([
    load(() => listGroups()),
    load(() =>
      all(
        (nextToken) =>
          client.send(
            new DescribeQueryDefinitionsCommand({
              nextToken,
              maxResults: 1000,
            }),
          ),
        (r) => r.queryDefinitions,
        (r) => r.nextToken,
      ),
    ),
    load(
      async () =>
        (await client.send(new DescribeQueriesCommand({ maxResults: 20 })))
          .queries ?? [],
    ),
    selected[0]
      ? load(
          async () =>
            (
              await client.send(
                new GetLogGroupFieldsCommand({ logGroupName: selected[0] }),
              )
            ).logGroupFields ?? [],
        )
      : Promise.resolve(null),
  ]);
  const names = groups.ok ? groups.value.map((g) => g.logGroupName!) : [];
  const text = q ?? DEFAULT;
  const save = (
    <Sheet
      title="Save query"
      label="Save query"
      icon={<Bookmark size={16} />}
      testId="save-query"
    >
      <ActionForm action={saveQuery} submit="Save" testId="save-query">
        <Field
          label="Name"
          rule={PutQueryDefinition.name}
          taken={saved.ok ? saved.value.map((d) => d.name!) : []}
          generate="name"
        >
          <input name="name" autoFocus />
        </Field>
        <Field label="Query" rule={PutQueryDefinition.queryString}>
          <textarea
            name="query"
            rows={4}
            className="code-editor"
            defaultValue={text}
          />
        </Field>
        <input type="hidden" name="groups" value={selected.join(",")} />
        <input type="hidden" name="language" value={language} />
      </ActionForm>
    </Sheet>
  );
  return (
    <Page
      title="Logs Insights"
      icon={ICONS.logs}
      back={{ href: "/logs", label: "Log groups" }}
      actions={save}
    >
      <ActionForm action={startQuery} submit="Run query" testId="run-query">
        <div className="form-grid">
          <Field label="Log groups" rule={{}}>
            <select
              name="groups"
              multiple
              size={Math.min(6, Math.max(2, names.length))}
              defaultValue={selected}
              aria-label="Log groups"
            >
              {names.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Language" rule={StartQuery.queryLanguage}>
            <select name="language" defaultValue={language}>
              {LANGUAGES.map(([k, l]) => (
                <option key={k} value={k}>
                  {l}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Time range" rule={{}}>
            <select name="minutes" defaultValue={minutes}>
              {RANGES.map(([m, l]) => (
                <option key={m} value={m}>
                  {l}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Limit" rule={StartQuery.limit}>
            <input name="limit" type="number" defaultValue={1000} />
          </Field>
        </div>
        <Field label="Query" rule={StartQuery.queryString}>
          <textarea
            name="query"
            rows={5}
            className="code-editor"
            defaultValue={text}
            required
          />
        </Field>
        {fields && fields.ok && fields.value.length > 0 && (
          <div className="chips" aria-label="Discovered fields">
            {fields.value.slice(0, 30).map((f) => (
              <span
                key={f.name}
                className="chip"
                title={`${f.percent}% of events`}
              >
                {f.name}
              </span>
            ))}
          </div>
        )}
      </ActionForm>
      {query && <Results id={query} />}
      <Section
        title="Saved queries"
        count={saved.ok ? saved.value.length : undefined}
        plain
      >
        {saved.ok ? (
          <List
            label="Saved queries"
            empty={<Empty icon={ICONS.logs} />}
            rows={saved.value.map((d) => ({
              key: d.queryDefinitionId!,
              icon: <Bookmark size={16} />,
              title: d.name,
              subtitle: (
                <code className="clip">
                  {d.queryString?.replace(/\s+/g, " ")}
                </code>
              ),
              href: href({
                q: d.queryString,
                groups: d.logGroupNames?.join(","),
                language: d.queryLanguage,
              }),
              meta: (
                <>
                  {d.logGroupNames?.length ? (
                    <Pill>{d.logGroupNames.length} groups</Pill>
                  ) : null}
                  <span>{ago(d.lastModified)}</span>
                </>
              ),
              actions: (
                <ActionForm
                  action={deleteQuery.bind(null, d.queryDefinitionId!)}
                  submit={`Delete ${d.name}`}
                  icon={<Trash2 size={15} />}
                  tone="danger"
                  confirm={`Delete ${d.name}?`}
                />
              ),
            }))}
          />
        ) : (
          <ErrorNotice error={saved.error} />
        )}
      </Section>
      {recent.ok && recent.value.length > 0 && (
        <Section title="History" count={recent.value.length} plain>
          <List
            label="Recent queries"
            rows={recent.value.map((r) => ({
              key: r.queryId!,
              icon: <FileSearch size={16} />,
              title: (
                <code className="clip">
                  {r.queryString?.replace(/\s+/g, " ")}
                </code>
              ),
              subtitle: r.logGroupName ? r.logGroupName : undefined,
              href: href({
                id: r.queryId,
                q: r.queryString,
                groups: r.logGroupName,
                language: r.queryLanguage,
              }),
              meta: (
                <>
                  <Status tone={STATE_TONE[r.status ?? ""] ?? "neutral"}>
                    {r.status ?? ""}
                  </Status>
                  <span>{ago(r.createTime)}</span>
                </>
              ),
            }))}
          />
        </Section>
      )}
    </Page>
  );
}
