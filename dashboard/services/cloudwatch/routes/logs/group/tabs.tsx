import {
  DescribeLogStreamsCommand,
  DescribeMetricFiltersCommand,
  DescribeSubscriptionFiltersCommand,
  ListTagsForResourceCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { ago, all, bytes, load } from "@mws-dashboard/aws";
import { roleOptions } from "@mws-dashboard/aws/auto";
import {
  ActionForm,
  AutoPick,
  AwsIcon,
  Empty,
  ErrorNotice,
  Field,
  List,
  More,
  Pill,
  Section,
  Sheet,
  Tags,
} from "@mws-dashboard/ui";
import {
  FilterLogEvents,
  PutMetricFilter,
  PutSubscriptionFilter,
  TagResource,
  TestMetricFilter,
} from "@mws-dashboard/ui/model/logs";
import { ArrowRight, FlaskConical, Radio, Trash2, X } from "lucide-react";
import Link from "next/link";

import {
  ICONS,
  arnHref,
  arnIcon,
  arnName,
  groupHref,
  logs,
} from "../../../lib/clients";
import { newestEvents } from "../../../lib/events";
import { Tail } from "../../../lib/live";
import {
  addTags,
  deleteMetricFilter,
  deleteStream,
  deleteSubscriptionFilter,
  putMetricFilter,
  putSubscriptionFilter,
  removeTag,
  testMetricFilter,
} from "../actions";

const LEVEL = /\b(ERROR|FATAL|CRITICAL|Exception|Traceback|WARN(ING)?)\b/;

/** An event's level: a JSON `level` field first, then a word in the text. */
function level(message: string | undefined): "bad" | "warn" | undefined {
  const m = message ?? "";
  if (m.trimStart().startsWith("{")) {
    try {
      const v = JSON.parse(m) as Record<string, unknown>;
      const l = String(
        v.level ?? v.severity ?? v.levelname ?? "",
      ).toUpperCase();
      if (/^(ERROR|FATAL|CRITICAL|ERR)$/.test(l)) return "bad";
      if (/^WARN/.test(l)) return "warn";
      if (l) return undefined;
    } catch {
      // not JSON after all
    }
  }
  const word = m.match(LEVEL)?.[1];
  return word ? (word.startsWith("WARN") ? "warn" : "bad") : undefined;
}

/** JSON messages indented, the rest as written. */
function pretty(message: string | undefined) {
  const m = message ?? "";
  if (!m.trimStart().startsWith("{")) return m;
  try {
    return JSON.stringify(JSON.parse(m), null, 2);
  } catch {
    return m;
  }
}

const RANGES: [string, number][] = [
  ["5m", 5 * 60_000],
  ["1h", 3600_000],
  ["1d", 86_400_000],
  ["1w", 7 * 86_400_000],
];

export type Search = {
  name?: string;
  stream?: string;
  prefix?: string;
  pattern?: string;
  before?: string;
  range?: string;
  live?: string;
  token?: string;
  tab?: string;
};

export async function EventsTab({
  name,
  search,
  now,
  multiStream,
}: {
  name: string;
  search: Search;
  now: number;
  multiStream: boolean;
}) {
  const { stream, prefix, pattern, before, range, live } = search;
  const after = RANGES.find(([k]) => k === range)?.[1];
  const events = await load(() =>
    newestEvents({
      group: name,
      streams: stream ? [stream] : undefined,
      prefix: stream ? undefined : prefix,
      pattern,
      before: before ? Number(before) : undefined,
      after: after ? now - after : undefined,
    }),
  );
  const keep = (extra: Record<string, string | undefined>) => {
    const p: Record<string, string> = { name };
    for (const [k, v] of Object.entries({
      stream,
      prefix,
      pattern,
      range,
      live,
      ...extra,
    }))
      if (v) p[k] = v;
    return `/logs/group?${new URLSearchParams(p)}`;
  };
  return (
    <>
      <form className="search-page-form" action="/logs/group">
        <input type="hidden" name="name" value={name} />
        {stream && <input type="hidden" name="stream" value={stream} />}
        {range && <input type="hidden" name="range" value={range} />}
        {live && <input type="hidden" name="live" value={live} />}
        <Field label="Filter pattern" rule={FilterLogEvents.filterPattern}>
          <input
            name="pattern"
            defaultValue={pattern}
            placeholder='ERROR or { $.level = "warn" }'
            aria-label="Filter pattern"
          />
        </Field>
        {!stream && (
          <Field
            label="Stream prefix"
            rule={FilterLogEvents.logStreamNamePrefix}
          >
            <input
              name="prefix"
              defaultValue={prefix}
              placeholder="Stream prefix"
              aria-label="Stream prefix"
            />
          </Field>
        )}
        {/* Enter submits a form with two fields only when it has a submit button. */}
        <button type="submit" hidden />
      </form>
      <div className="chips">
        {[["", "All"], ...RANGES].map(([k]) => (
          <Link
            key={String(k) || "all"}
            className="chip"
            href={keep({ range: String(k) || undefined, before: undefined })}
            aria-current={(range ?? "") === k ? "true" : undefined}
          >
            {(range ?? "") === k ? (
              <b>{String(k) || "All"}</b>
            ) : (
              String(k) || "All"
            )}
          </Link>
        ))}
        <Link
          className="chip"
          href={keep({ live: live ? undefined : "1", before: undefined })}
          aria-pressed={!!live}
          data-testid="live-tail"
        >
          <Radio size={12} aria-hidden /> {live ? <b>Live</b> : "Live"}
        </Link>
        {stream && (
          <span className="chip">
            {stream}
            <Link
              className="icon-button plain"
              href={keep({ stream: undefined })}
              aria-label="All streams"
            >
              <X size={11} />
            </Link>
          </span>
        )}
      </div>
      {live && !before && <Tail />}
      <Section plain>
        {events.ok ? (
          events.value.events.length ? (
            <>
              <ol className="log-events" aria-label="Log events">
                {events.value.events.map((e) => (
                  <li
                    key={
                      e.eventId ??
                      `${e.logStreamName}-${e.timestamp}-${e.message}`
                    }
                    className={level(e.message)}
                  >
                    <time
                      dateTime={new Date(e.timestamp ?? 0).toISOString()}
                      title={new Date(e.timestamp ?? 0).toISOString()}
                    >
                      {new Date(e.timestamp ?? 0)
                        .toISOString()
                        .slice(
                          now - (e.timestamp ?? 0) > 86_400_000 ? 5 : 11,
                          23,
                        )
                        .replace("T", " ")}
                    </time>
                    <pre>{pretty(e.message)}</pre>
                    {!stream && multiStream && (
                      <Link
                        className="log-stream"
                        href={keep({
                          stream: e.logStreamName!,
                          before: undefined,
                        })}
                      >
                        {e.logStreamName}
                      </Link>
                    )}
                  </li>
                ))}
              </ol>
              <More
                shown={events.value.events.length}
                noun="events"
                href={
                  events.value.older !== undefined
                    ? keep({
                        before: String(events.value.older),
                        live: undefined,
                      })
                    : undefined
                }
              />
            </>
          ) : (
            <Empty icon={ICONS.logs} />
          )
        ) : (
          <ErrorNotice error={events.error} />
        )}
      </Section>
    </>
  );
}

export async function StreamsTab({
  name,
  token,
}: {
  name: string;
  token?: string;
}) {
  const streams = await load(async () =>
    (await logs()).send(
      new DescribeLogStreamsCommand({
        logGroupName: name,
        orderBy: "LastEventTime",
        descending: true,
        limit: 50,
        nextToken: token,
      }),
    ),
  );
  if (!streams.ok) return <ErrorNotice error={streams.error} />;
  const list = streams.value.logStreams ?? [];
  const next = streams.value.nextToken;
  return (
    <Section plain>
      <List
        label="Log streams"
        empty={<Empty icon={ICONS.logs} />}
        rows={list.map((s) => ({
          key: s.logStreamName!,
          icon: <AwsIcon icon={ICONS.logs} size={18} />,
          title: s.logStreamName,
          subtitle: s.firstEventTimestamp
            ? `${new Date(s.firstEventTimestamp).toISOString().slice(0, 19).replace("T", " ")} → ${new Date(s.lastEventTimestamp ?? s.firstEventTimestamp).toISOString().slice(0, 19).replace("T", " ")}`
            : undefined,
          href: groupHref(name, { stream: s.logStreamName! }),
          meta: (
            <>
              {s.storedBytes ? <span>{bytes(s.storedBytes)}</span> : null}
              <Pill>{ago(s.lastEventTimestamp ?? s.creationTime)}</Pill>
            </>
          ),
          actions: (
            <ActionForm
              action={deleteStream.bind(null, name, s.logStreamName!)}
              submit={`Delete ${s.logStreamName}`}
              icon={<Trash2 size={15} />}
              tone="danger"
              confirm={`Delete ${s.logStreamName} and its events?`}
            />
          ),
        }))}
      />
      <More
        shown={list.length}
        noun="streams"
        href={
          next
            ? `${groupHref(name, { tab: "streams", token: next })}`
            : undefined
        }
      />
    </Section>
  );
}

const MF = PutMetricFilter.metricTransformations.item!.fields!;

export async function MetricFiltersTab({
  name,
  namespaces,
}: {
  name: string;
  namespaces: string[];
}) {
  const filters = await load(async () => {
    const c = await logs();
    return all(
      (nextToken) =>
        c.send(
          new DescribeMetricFiltersCommand({ logGroupName: name, nextToken }),
        ),
      (r) => r.metricFilters,
      (r) => r.nextToken,
    );
  });
  const create = (
    <Sheet
      title="Create metric filter"
      label="Create metric filter"
      testId="create-metric-filter"
    >
      <ActionForm
        action={putMetricFilter.bind(null, name)}
        submit="Create"
        testId="create-metric-filter"
      >
        <Field
          label="Name"
          rule={PutMetricFilter.filterName}
          taken={filters.ok ? filters.value.map((f) => f.filterName!) : []}
          generate="name"
          unique
        >
          <input name="name" autoFocus />
        </Field>
        <Field
          label="Filter pattern"
          rule={{ ...PutMetricFilter.filterPattern, required: false }}
          hint="ERROR, or { $.latency > 500 }"
        >
          <input name="pattern" />
        </Field>
        <div className="form-grid">
          <Field
            label="Namespace"
            rule={{ ...MF.metricNamespace, minLength: 1 }}
            known={namespaces}
          >
            <input name="namespace" list="mf-namespaces" />
          </Field>
          <Field label="Metric" rule={{ ...MF.metricName, minLength: 1 }}>
            <input name="metric" />
          </Field>
          <Field label="Value" rule={MF.metricValue} hint="1, or $.field">
            <input name="value" defaultValue="1" />
          </Field>
          <Field label="Default value" rule={MF.defaultValue}>
            <input name="default" type="number" step="any" />
          </Field>
          <Field label="Unit" rule={MF.unit}>
            <select name="unit" defaultValue="">
              <option value="">None</option>
              {(MF.unit?.enum ?? []).map((u) => (
                <option key={u}>{u}</option>
              ))}
            </select>
          </Field>
        </div>
        <datalist id="mf-namespaces">
          {namespaces.map((n) => (
            <option key={n} value={n} />
          ))}
        </datalist>
        <Field
          label="Dimensions"
          rule={{ format: "pairs", maxLength: 2048 }}
          hint="Name=$.field, up to 3"
        >
          <textarea name="dims" rows={2} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  const test = (
    <Sheet
      title="Test pattern"
      label="Test pattern"
      icon={<FlaskConical size={16} />}
      testId="test-metric-filter"
    >
      <ActionForm
        action={testMetricFilter}
        submit="Test"
        testId="test-metric-filter"
      >
        <Field
          label="Filter pattern"
          rule={{ ...TestMetricFilter.filterPattern, required: false }}
        >
          <input name="pattern" />
        </Field>
        <Field
          label="Sample events"
          rule={{ required: true }}
          hint="One per line, up to 50"
        >
          <textarea name="samples" rows={5} className="code-editor" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Section
      title="Metric filters"
      count={filters.ok ? filters.value.length : undefined}
      actions={
        <>
          {test}
          {create}
        </>
      }
      plain
    >
      {filters.ok ? (
        <List
          label="Metric filters"
          empty={<Empty icon={ICONS.metrics} />}
          rows={filters.value.map((f) => {
            const t = f.metricTransformations?.[0];
            return {
              key: f.filterName!,
              icon: <AwsIcon icon={ICONS.metrics} size={20} />,
              title: f.filterName,
              subtitle: (
                <>
                  <code>{f.filterPattern || "(all events)"}</code>{" "}
                  <ArrowRight size={11} aria-hidden /> {t?.metricNamespace}/
                  {t?.metricName} = {t?.metricValue}
                  {t?.dimensions && Object.keys(t.dimensions).length
                    ? ` · ${Object.entries(t.dimensions)
                        .map(([k, v]) => `${k}=${v}`)
                        .join(", ")}`
                    : ""}
                </>
              ),
              href: t
                ? `/metrics?${new URLSearchParams({ ns: t.metricNamespace!, ...(t.dimensions && Object.keys(t.dimensions).length ? {} : { metric: t.metricName!, dims: "[]" }) })}`
                : undefined,
              meta: <span>{ago(f.creationTime)}</span>,
              actions: (
                <ActionForm
                  action={deleteMetricFilter.bind(null, name, f.filterName!)}
                  submit={`Delete ${f.filterName}`}
                  icon={<Trash2 size={15} />}
                  tone="danger"
                  confirm={`Delete ${f.filterName}?`}
                />
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={filters.error} />
      )}
    </Section>
  );
}

export async function SubscriptionsTab({
  name,
  arn,
  targets,
}: {
  name: string;
  arn: string;
  targets: string[];
}) {
  const [filters, roles] = await Promise.all([
    load(async () => {
      const c = await logs();
      return all(
        (nextToken) =>
          c.send(
            new DescribeSubscriptionFiltersCommand({
              logGroupName: name,
              nextToken,
            }),
          ),
        (r) => r.subscriptionFilters,
        (r) => r.nextToken,
      );
    }),
    roleOptions("logs.amazonaws.com"),
  ]);
  const create = (
    <Sheet
      title="Create subscription filter"
      label="Create subscription filter"
      testId="create-subscription"
    >
      <ActionForm
        action={putSubscriptionFilter.bind(null, name, arn)}
        submit="Start streaming"
        testId="create-subscription"
      >
        <Field
          label="Name"
          rule={PutSubscriptionFilter.filterName}
          taken={filters.ok ? filters.value.map((f) => f.filterName!) : []}
          generate="name"
          unique
        >
          <input name="name" autoFocus />
        </Field>
        <Field
          label="Destination"
          rule={{ ...PutSubscriptionFilter.destinationArn, format: "arn" }}
          known={targets}
          hint="Lambda function, Kinesis stream, Firehose stream or Logs destination"
        >
          <input name="destination" list="subscription-targets" />
        </Field>
        <datalist id="subscription-targets">
          {targets.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
        <Field
          label="Filter pattern"
          rule={{ ...PutSubscriptionFilter.filterPattern, required: false }}
          hint="Empty sends every event"
        >
          <input name="pattern" />
        </Field>
        <AutoPick
          name="role"
          label="Role (Kinesis and Firehose)"
          creates="CWLtoSubscriptionDestinationRole"
          options={roles}
          testId="subscription-role"
        />
        <Field
          label="Distribution (Kinesis)"
          rule={PutSubscriptionFilter.distribution}
        >
          <select name="distribution" defaultValue="ByLogStream">
            <option value="ByLogStream">By log stream</option>
            <option value="Random">Random</option>
          </select>
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Section
      title="Subscription filters"
      count={filters.ok ? filters.value.length : undefined}
      actions={create}
      plain
    >
      {filters.ok ? (
        <List
          label="Subscription filters"
          empty={<Empty icon={ICONS.logs} />}
          rows={filters.value.map((f) => ({
            key: f.filterName!,
            icon: <AwsIcon icon={arnIcon(f.destinationArn)} size={20} />,
            title: f.filterName,
            subtitle: (
              <>
                <code>{f.filterPattern || "(all events)"}</code>{" "}
                <ArrowRight size={11} aria-hidden />{" "}
                {arnName(f.destinationArn ?? "")}
              </>
            ),
            href: arnHref(f.destinationArn),
            meta: (
              <>
                {f.distribution && f.destinationArn?.includes(":kinesis:") ? (
                  <Pill>{f.distribution}</Pill>
                ) : null}
                <span>{ago(f.creationTime)}</span>
              </>
            ),
            actions: (
              <ActionForm
                action={deleteSubscriptionFilter.bind(
                  null,
                  name,
                  f.filterName!,
                )}
                submit={`Delete ${f.filterName}`}
                icon={<Trash2 size={15} />}
                tone="danger"
                confirm={`Stop streaming ${f.filterName}?`}
              />
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={filters.error} />
      )}
    </Section>
  );
}

export async function TagsTab({ arn }: { arn: string }) {
  const tags = await load(
    async () =>
      (
        await (
          await logs()
        ).send(new ListTagsForResourceCommand({ resourceArn: arn }))
      ).tags ?? {},
  );
  const add = (
    <Sheet title="Add tags" label="Add tags" testId="add-log-tags">
      <ActionForm
        action={addTags.bind(null, arn)}
        submit="Add"
        testId="add-log-tags"
      >
        <Field label="Tags" rule={{ ...TagResource.tags, format: "tags" }}>
          <textarea name="tags" rows={3} placeholder="team=payments" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Section title="Tags" actions={add} plain>
      {tags.ok ? (
        <List
          label="Tags"
          empty={<Empty />}
          rows={Object.entries(tags.value).map(([k, v]) => ({
            key: k,
            title: <Tags tags={{ [k]: v }} />,
            actions: (
              <ActionForm
                action={removeTag.bind(null, arn, k)}
                submit={`Remove ${k}`}
                icon={<X size={14} />}
                tone="danger"
              />
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={tags.error} />
      )}
    </Section>
  );
}
