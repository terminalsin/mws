import {
  DescribeAlarmContributorsCommand,
  DescribeAlarmHistoryCommand,
  DescribeAlarmsCommand,
  GetMetricDataCommand,
  type CompositeAlarm,
  type HistoryItemType,
  type MetricAlarm,
  type MetricDataQuery,
} from "@aws-sdk/client-cloudwatch";
import { ago, load, mws, when } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  CodeBlock,
  Empty,
  ErrorNotice,
  Facts,
  Field,
  List,
  More,
  Page,
  Pill,
  Section,
  Segments,
  Sheet,
  Specs,
  Status,
  Tags,
} from "@mws-dashboard/ui";
import { SetAlarmState } from "@mws-dashboard/ui/model/cloudwatch";
import {
  BellOff,
  BellRing,
  Clock,
  FileSearch,
  GitMerge,
  History,
  Pencil,
  Repeat,
  Siren,
  Trash2,
} from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { ListTagsForResourceCommand } from "@aws-sdk/client-cloudwatch";

import { AlarmForm, CompositeForm, period } from "../../../lib/alarm-form";
import { formOptions, rule } from "../../../lib/alarms";
import {
  ALARM_TONE,
  ICONS,
  alarmHref,
  arnHref,
  arnIcon,
  arnName,
  cloudwatch,
  dimsText,
  groupHref,
  listAlarms,
  metricHref,
  sourceIcon,
  type AnyAlarm,
} from "../../../lib/clients";
import { LineChart } from "../../metrics/chart";
import {
  deleteAlarm,
  saveAlarm,
  saveComposite,
  setActions,
  setStateWithReason,
} from "../actions";

type Props = {
  searchParams: Promise<{
    name?: string;
    tab?: string;
    type?: string;
    token?: string;
  }>;
};

export async function generateMetadata({
  searchParams,
}: Props): Promise<Metadata> {
  return { title: (await searchParams).name ?? "Alarm" };
}

const TABS = ["details", "actions", "history", "parents"] as const;

async function find(name: string): Promise<AnyAlarm | undefined> {
  const out = await (
    await cloudwatch()
  ).send(
    new DescribeAlarmsCommand({
      AlarmNames: [name],
      AlarmTypes: ["MetricAlarm", "CompositeAlarm", "LogAlarm"],
    }),
  );
  const m = out.MetricAlarms?.[0];
  if (m) return { ...m, kind: "metric" };
  const c = out.CompositeAlarms?.[0];
  if (c) return { ...c, kind: "composite" };
  const l = out.LogAlarms?.[0];
  if (l) return { ...l, kind: "log" };
  return undefined;
}

/** The alarm's metric over the last three hours (on MWS's clock), at its own
 * period and statistic, with the threshold drawn across. */
async function AlarmChart({ alarm }: { alarm: MetricAlarm }) {
  const data = await load(async () => {
    const clock = await mws<{ now: string }>("/_mws/clock");
    const end = new Date(clock.now);
    const queries: MetricDataQuery[] = alarm.Metrics?.length
      ? alarm.Metrics.map((m) => ({ ...m, ReturnData: m.ReturnData ?? true }))
      : [
          {
            Id: "m1",
            MetricStat: {
              Metric: {
                Namespace: alarm.Namespace,
                MetricName: alarm.MetricName,
                Dimensions: alarm.Dimensions,
              },
              Period: alarm.Period ?? 60,
              Stat: alarm.Statistic ?? alarm.ExtendedStatistic ?? "Average",
            },
          },
        ];
    const span = Math.max(
      3 * 3600_000,
      (alarm.Period ?? 60) *
        1000 *
        Math.max(alarm.EvaluationPeriods ?? 1, 1) *
        4,
    );
    const out = await (
      await cloudwatch()
    ).send(
      new GetMetricDataCommand({
        StartTime: new Date(end.getTime() - span),
        EndTime: new Date(end.getTime() + 60_000),
        MetricDataQueries: queries,
      }),
    );
    return out.MetricDataResults ?? [];
  });
  if (!data.ok) return <ErrorNotice error={data.error} />;
  const main =
    data.value.find((r) => r.Id !== alarm.ThresholdMetricId) ?? data.value[0];
  const points = (main?.Timestamps ?? [])
    .map((t, i) => ({ t, v: main!.Values![i] }))
    .sort((a, b) => a.t.getTime() - b.t.getTime());
  if (!points.length) return <Empty icon={ICONS.metrics} />;
  return (
    <LineChart
      points={points}
      label="Alarm chart"
      threshold={alarm.ThresholdMetricId ? undefined : alarm.Threshold}
    />
  );
}

const HISTORY_TYPES: { id: HistoryItemType | ""; label: string }[] = [
  { id: "", label: "All" },
  { id: "StateUpdate", label: "State" },
  { id: "ConfigurationUpdate", label: "Configuration" },
  { id: "Action", label: "Action" },
];

async function HistoryTab({
  name,
  type,
  token,
  base,
}: {
  name: string;
  type?: string;
  token?: string;
  base: string;
}) {
  const history = await load(async () =>
    (await cloudwatch()).send(
      new DescribeAlarmHistoryCommand({
        AlarmName: name,
        HistoryItemType: (type || undefined) as HistoryItemType | undefined,
        NextToken: token,
        MaxRecords: 50,
        ScanBy: "TimestampDescending",
        AlarmTypes: ["MetricAlarm", "CompositeAlarm", "LogAlarm"],
      }),
    ),
  );
  if (!history.ok) return <ErrorNotice error={history.error} />;
  const items = history.value.AlarmHistoryItems ?? [];
  return (
    <Section plain>
      <Segments
        label="History type"
        items={HISTORY_TYPES.map((t) => ({
          label: t.label,
          href: `${base}&tab=history${t.id ? `&type=${t.id}` : ""}`,
          active: (type ?? "") === t.id,
        }))}
      />
      <ol className="log-events" aria-label="Alarm history">
        {items.map((h, i) => {
          let data: { newState?: { stateValue?: string } } = {};
          try {
            data = JSON.parse(h.HistoryData ?? "{}");
          } catch {
            // not JSON
          }
          const tone =
            h.HistoryItemType === "StateUpdate"
              ? data.newState?.stateValue === "ALARM"
                ? "bad"
                : undefined
              : h.HistoryItemType === "Action" &&
                  /fail/i.test(h.HistorySummary ?? "")
                ? "warn"
                : undefined;
          return (
            <li key={`${h.Timestamp?.toISOString()}-${i}`} className={tone}>
              <time
                dateTime={h.Timestamp?.toISOString()}
                title={h.Timestamp?.toISOString()}
              >
                {when(h.Timestamp)}
              </time>
              <pre>
                <Pill>{h.HistoryItemType}</Pill> {h.HistorySummary}
              </pre>
              {h.HistoryData && (
                <details>
                  <summary className="muted">Data</summary>
                  <CodeBlock value={h.HistoryData} />
                </details>
              )}
            </li>
          );
        })}
      </ol>
      {items.length === 0 && <Empty icon={ICONS.alarm} />}
      <More
        shown={items.length}
        noun="entries"
        href={
          history.value.NextToken
            ? `${base}&tab=history${type ? `&type=${type}` : ""}&token=${encodeURIComponent(history.value.NextToken)}`
            : undefined
        }
      />
    </Section>
  );
}

function ActionsTab({ alarm }: { alarm: AnyAlarm }) {
  const groups: [string, string, string[] | undefined][] = [
    ["ALARM", "In alarm", alarm.AlarmActions],
    ["OK", "OK", alarm.OKActions],
    ["INSUFFICIENT_DATA", "Insufficient data", alarm.InsufficientDataActions],
  ];
  const any = groups.some(([, , a]) => a?.length);
  if (!any) return <Empty icon={ICONS.alarm} />;
  return (
    <>
      {!alarm.ActionsEnabled && (
        <div className="banner" role="status">
          <BellOff size={14} aria-hidden /> Actions are muted
        </div>
      )}
      {groups
        .filter(([, , a]) => a?.length)
        .map(([state, title, actions]) => (
          <Section
            key={state}
            title={
              <Status tone={ALARM_TONE[state] ?? "neutral"}>{title}</Status>
            }
            count={actions!.length}
            plain
          >
            <List
              label={`${title} actions`}
              rows={actions!.map((a) => ({
                key: a,
                icon: <AwsIcon icon={arnIcon(a)} size={20} />,
                title: arnName(a),
                subtitle: a,
                href: arnHref(a),
              }))}
            />
          </Section>
        ))}
    </>
  );
}

function Details({
  alarm,
  children,
  contributors,
}: {
  alarm: AnyAlarm;
  children: CompositeAlarm[] | MetricAlarm[] | null;
  contributors: {
    id: string;
    attrs: Record<string, string>;
    reason?: string;
  }[];
}) {
  const reasonData = alarm.StateReasonData;
  return (
    <>
      <Section>
        <Facts
          items={[
            [
              "State",
              <Status
                key="s"
                tone={ALARM_TONE[alarm.StateValue ?? ""] ?? "neutral"}
              >
                {alarm.StateValue}
              </Status>,
            ],
            ["Reason", alarm.StateReason],
            alarm.AlarmDescription && ["Description", alarm.AlarmDescription],
            ["Rule", <code key="r">{rule(alarm)}</code>],
            alarm.kind === "metric" &&
              alarm.MetricName && [
                "Metric",
                <Link
                  key="m"
                  href={metricHref(
                    alarm.Namespace!,
                    alarm.MetricName,
                    alarm.Dimensions,
                  )}
                >
                  {alarm.Namespace} · {alarm.MetricName}
                  {alarm.Dimensions?.length
                    ? ` · ${dimsText(alarm.Dimensions)}`
                    : ""}
                </Link>,
              ],
            alarm.kind === "metric" &&
              alarm.TreatMissingData && [
                "Missing data",
                alarm.TreatMissingData,
              ],
            alarm.kind === "metric" &&
              alarm.EvaluationState && ["Evaluation", alarm.EvaluationState],
            alarm.kind === "composite" &&
              alarm.ActionsSuppressor && [
                "Suppressor",
                <Link key="sup" href={alarmHref(alarm.ActionsSuppressor)}>
                  {alarm.ActionsSuppressor}
                </Link>,
              ],
            alarm.kind === "composite" &&
              alarm.ActionsSuppressedBy && [
                "Suppressed by",
                `${alarm.ActionsSuppressedBy}: ${alarm.ActionsSuppressedReason ?? ""}`,
              ],
            alarm.kind === "log" &&
              alarm.ScheduledQueryConfiguration && [
                "Schedule",
                alarm.ScheduledQueryConfiguration.ScheduleConfiguration
                  ?.ScheduleExpression,
              ],
            alarm.kind === "log" &&
              alarm.ScheduledQueryConfiguration?.LogGroupIdentifiers
                ?.length && [
                "Log groups",
                <span key="g" className="chips">
                  {alarm.ScheduledQueryConfiguration.LogGroupIdentifiers.map(
                    (g) => (
                      <Link
                        key={g}
                        className="chip"
                        href={groupHref(
                          g.startsWith("arn:")
                            ? (g.split(":log-group:")[1]?.replace(/:\*$/, "") ??
                                g)
                            : g,
                        )}
                      >
                        {g.split(":").pop()}
                      </Link>
                    ),
                  )}
                </span>,
              ],
            alarm.kind === "log" &&
              alarm.ScheduledQueryConfiguration?.ScheduledQueryRoleARN && [
                "Role",
                <Link
                  key="role"
                  href={
                    arnHref(
                      alarm.ScheduledQueryConfiguration.ScheduledQueryRoleARN,
                    ) ?? "#"
                  }
                >
                  {arnName(
                    alarm.ScheduledQueryConfiguration.ScheduledQueryRoleARN,
                  )}
                </Link>,
              ],
            ["Updated", when(alarm.AlarmConfigurationUpdatedTimestamp)],
          ]}
        />
      </Section>
      {alarm.kind === "metric" && (
        <Section title="Graph">
          <AlarmChart alarm={alarm} />
        </Section>
      )}
      {alarm.kind === "log" &&
        alarm.ScheduledQueryConfiguration?.QueryString && (
          <Section title="Query" icon={<FileSearch size={15} />}>
            <CodeBlock value={alarm.ScheduledQueryConfiguration.QueryString} />
          </Section>
        )}
      {alarm.kind === "metric" && alarm.Metrics?.length ? (
        <Section title="Metric math">
          <CodeBlock value={JSON.stringify(alarm.Metrics)} />
        </Section>
      ) : null}
      {children && (
        <Section title="Alarms in the rule" count={children.length} plain>
          <List
            label="Child alarms"
            rows={children.map((c) => ({
              key: c.AlarmArn!,
              icon: <AwsIcon icon={ICONS.alarm} size={20} />,
              title: c.AlarmName,
              href: alarmHref(c.AlarmName!),
              meta: (
                <Status tone={ALARM_TONE[c.StateValue ?? ""] ?? "neutral"}>
                  {c.StateValue?.toLowerCase().replace("_", " ") ?? ""}
                </Status>
              ),
            }))}
          />
        </Section>
      )}
      {contributors.length > 0 && (
        <Section title="Contributors" count={contributors.length} plain>
          <List
            label="Contributors"
            rows={contributors.map((c) => ({
              key: c.id,
              icon: <Siren size={16} />,
              title: Object.entries(c.attrs)
                .map(([k, v]) => `${k}=${v}`)
                .join(", "),
              subtitle: c.reason,
            }))}
          />
        </Section>
      )}
      {reasonData && (
        <details>
          <summary className="muted">State reason data</summary>
          <CodeBlock value={reasonData} />
        </details>
      )}
    </>
  );
}

export default async function AlarmPage({ searchParams }: Props) {
  const { name = "", tab: rawTab, type, token } = await searchParams;
  const tab = (TABS as readonly string[]).includes(rawTab ?? "")
    ? rawTab!
    : "details";
  const back = { href: "/alarms", label: "Alarms" };
  const found = await load(() => find(name));
  if (!found.ok || !found.value) {
    return (
      <Page title={name} icon={ICONS.alarm} back={back}>
        <ErrorNotice
          error={found.ok ? `Alarm ${name} does not exist.` : found.error}
        />
      </Page>
    );
  }
  const alarm = found.value;
  const client = await cloudwatch();
  const [options, all, parents, children, contributors, tags] =
    await Promise.all([
      formOptions(),
      load(listAlarms),
      load(
        async () =>
          (
            await client.send(
              new DescribeAlarmsCommand({
                ParentsOfAlarmName: name,
                AlarmTypes: ["CompositeAlarm"],
              }),
            )
          ).CompositeAlarms ?? [],
      ),
      alarm.kind === "composite"
        ? load(async () => {
            const out = await client.send(
              new DescribeAlarmsCommand({
                ChildrenOfAlarmName: name,
                AlarmTypes: ["MetricAlarm", "CompositeAlarm"],
              }),
            );
            return [
              ...(out.MetricAlarms ?? []),
              ...(out.CompositeAlarms ?? []),
            ];
          })
        : Promise.resolve({ ok: true as const, value: null }),
      load(
        async () =>
          (
            await client.send(
              new DescribeAlarmContributorsCommand({ AlarmName: name }),
            )
          ).AlarmContributors ?? [],
      ),
      load(
        async () =>
          (
            await client.send(
              new ListTagsForResourceCommand({ ResourceARN: alarm.AlarmArn }),
            )
          ).Tags ?? [],
      ),
    ]);
  const names = all.ok
    ? all.value.map((a) => a.AlarmName!).filter((n) => n !== name)
    : [];
  const base = `/alarms/alarm?${new URLSearchParams({ name })}`;
  const tone = ALARM_TONE[alarm.StateValue ?? ""] ?? "neutral";
  const actionCount =
    (alarm.AlarmActions?.length ?? 0) +
    (alarm.OKActions?.length ?? 0) +
    (alarm.InsufficientDataActions?.length ?? 0);
  const contributorRows = contributors.ok
    ? contributors.value.map((c) => ({
        id: c.ContributorId!,
        attrs: c.ContributorAttributes ?? {},
        reason: c.StateReason,
      }))
    : [];
  const edit =
    alarm.kind === "metric" ? (
      <Sheet
        title={`Edit ${name}`}
        label="Edit alarm"
        icon={<Pencil size={16} />}
        testId="edit-alarm"
      >
        <AlarmForm
          {...options}
          alarm={alarm}
          taken={[]}
          action={saveAlarm.bind(null, name)}
          testId="edit-alarm"
        />
      </Sheet>
    ) : alarm.kind === "composite" ? (
      <Sheet
        title={`Edit ${name}`}
        label="Edit alarm"
        icon={<Pencil size={16} />}
        testId="edit-alarm"
      >
        <CompositeForm
          alarm={alarm}
          taken={[]}
          alarms={names}
          topics={options.topics}
          topicArn={options.topicArn}
          action={saveComposite.bind(null, name)}
          testId="edit-alarm"
        />
      </Sheet>
    ) : null;
  let body;
  if (tab === "actions") body = <ActionsTab alarm={alarm} />;
  else if (tab === "history")
    body = <HistoryTab name={name} type={type} token={token} base={base} />;
  else if (tab === "parents")
    body = parents.ok ? (
      <List
        label="Parent alarms"
        empty={<Empty icon={ICONS.alarm} />}
        rows={parents.value.map((p) => ({
          key: p.AlarmArn!,
          icon: <GitMerge size={18} />,
          title: p.AlarmName,
          subtitle: p.AlarmRule,
          href: alarmHref(p.AlarmName!),
          meta: (
            <Status tone={ALARM_TONE[p.StateValue ?? ""] ?? "neutral"}>
              {p.StateValue?.toLowerCase().replace("_", " ") ?? ""}
            </Status>
          ),
        }))}
      />
    ) : (
      <ErrorNotice error={parents.error} />
    );
  else
    body = (
      <Details
        alarm={alarm}
        children={children.ok ? children.value : null}
        contributors={contributorRows}
      />
    );
  return (
    <Page
      title={name}
      icon={
        alarm.kind === "metric" && alarm.Namespace
          ? (sourceIcon(alarm.Namespace) ?? ICONS.alarm)
          : ICONS.alarm
      }
      back={back}
      subtitle={alarm.AlarmArn}
      actions={
        <>
          {edit}
          <Sheet
            title="Set alarm state"
            label="Set state"
            icon={<Repeat size={16} />}
            testId="set-state"
          >
            <ActionForm
              action={setStateWithReason.bind(null, name)}
              submit="Set state"
              testId="set-state"
            >
              <Field label="State" rule={SetAlarmState.StateValue}>
                <select
                  name="state"
                  defaultValue={alarm.StateValue === "ALARM" ? "OK" : "ALARM"}
                >
                  <option value="ALARM">ALARM</option>
                  <option value="OK">OK</option>
                  <option value="INSUFFICIENT_DATA">INSUFFICIENT_DATA</option>
                </select>
              </Field>
              <Field
                label="Reason"
                rule={SetAlarmState.StateReason}
                hint={
                  alarm.kind === "metric"
                    ? "The next evaluation sets the real state again"
                    : undefined
                }
              >
                <input name="reason" defaultValue="Set from the MWS console" />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={setActions.bind(null, name, !alarm.ActionsEnabled)}
            submit={alarm.ActionsEnabled ? "Mute actions" : "Unmute actions"}
            icon={
              alarm.ActionsEnabled ? (
                <BellOff size={16} />
              ) : (
                <BellRing size={16} />
              )
            }
            testId="toggle-actions"
          />
          <ActionForm
            action={deleteAlarm.bind(null, name, true)}
            submit="Delete alarm"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${name}?`}
            testId="delete-alarm"
          />
        </>
      }
    >
      <Specs
        items={[
          {
            label: "State",
            icon: <Siren size={15} />,
            value: <Status tone={tone}>{alarm.StateValue ?? ""}</Status>,
          },
          {
            label: "Since",
            icon: <Clock size={15} />,
            value: ago(alarm.StateUpdatedTimestamp),
          },
          alarm.kind === "metric" &&
            !alarm.Metrics?.length && {
              label: "Period",
              icon: <History size={15} />,
              value: `${alarm.DatapointsToAlarm ?? alarm.EvaluationPeriods}/${alarm.EvaluationPeriods} × ${period(alarm.Period)}`,
            },
          !alarm.ActionsEnabled && {
            label: "Actions",
            icon: <BellOff size={15} />,
            value: "Muted",
          },
          alarm.kind === "composite" && {
            label: "Type",
            icon: <GitMerge size={15} />,
            value: "Composite",
          },
          alarm.kind === "log" && {
            label: "Type",
            icon: <FileSearch size={15} />,
            value: "Logs",
          },
        ]}
      />
      {tags.ok && tags.value.length > 0 && <Tags tags={tags.value} />}
      <Segments
        label="Alarm"
        items={[
          { label: "Details", href: base, active: tab === "details" },
          {
            label: "Actions",
            href: `${base}&tab=actions`,
            active: tab === "actions",
            count: actionCount || undefined,
          },
          {
            label: "History",
            href: `${base}&tab=history`,
            active: tab === "history",
          },
          {
            label: "Parent alarms",
            href: `${base}&tab=parents`,
            active: tab === "parents",
            count: parents.ok ? parents.value.length || undefined : undefined,
          },
        ]}
      />
      {body}
    </Page>
  );
}
