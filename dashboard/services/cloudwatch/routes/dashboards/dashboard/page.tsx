import {
  DescribeAlarmsCommand,
  GetDashboardCommand,
  GetMetricWidgetImageCommand,
} from "@aws-sdk/client-cloudwatch";
import { load } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Empty,
  ErrorNotice,
  Field,
  Page,
  Section,
  Segments,
  Sheet,
  Status,
  type Rule,
} from "@mws-dashboard/ui";
import {
  PutDashboard,
  PutMetricAlarm,
} from "@mws-dashboard/ui/model/cloudwatch";
import {
  BellRing,
  ChartLine,
  Code,
  FileSearch,
  Trash2,
  Type,
  X,
} from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import {
  ICONS,
  alarmHref,
  arnName,
  cloudwatch,
  listAlarms,
} from "../../../lib/clients";
import { STATISTICS } from "../../../lib/alarm-form";
import { formOptions } from "../../../lib/alarms";
import {
  addAlarmWidget,
  addMetricWidget,
  addTextWidget,
  deleteDashboard,
  removeWidget,
  saveSource,
} from "../actions";

type Props = { searchParams: Promise<{ name?: string; range?: string }> };

export async function generateMetadata({
  searchParams,
}: Props): Promise<Metadata> {
  return { title: (await searchParams).name ?? "Dashboard" };
}

const RANGES: [string, string][] = [
  ["1h", "-PT1H"],
  ["3h", "-PT3H"],
  ["12h", "-PT12H"],
  ["1d", "-P1D"],
  ["1w", "-P7D"],
];

type Widget = {
  type?: string;
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  properties?: Record<string, unknown>;
};

/** A metric widget as MWS draws it (GetMetricWidgetImage renders a real PNG). */
async function MetricWidget({
  properties,
  start,
}: {
  properties: Record<string, unknown>;
  start: string;
}) {
  const image = await load(async () => {
    const out = await (
      await cloudwatch()
    ).send(
      new GetMetricWidgetImageCommand({
        MetricWidget: JSON.stringify({
          ...properties,
          start,
          width: 640,
          height: 280,
        }),
        OutputFormat: "png",
      }),
    );
    return Buffer.from(out.MetricWidgetImage ?? new Uint8Array()).toString(
      "base64",
    );
  });
  if (!image.ok) return <ErrorNotice error={image.error} />;
  // eslint-disable-next-line @next/next/no-img-element
  return (
    <img
      src={`data:image/png;base64,${image.value}`}
      alt={String(properties.title ?? "Metric widget")}
      style={{ width: "100%", height: "auto", display: "block" }}
    />
  );
}

/** The alarms an alarm widget lists, with their state. */
function AlarmWidget({
  arns,
  states,
}: {
  arns: string[];
  states: Map<string, string>;
}) {
  return (
    <ul className="list" aria-label="Alarm widget">
      {arns.map((a) => {
        const name = arnName(a);
        const state = states.get(name);
        return (
          <li key={a} className="row">
            <Link className="row-main" href={alarmHref(name)}>
              <span className="row-icon">
                <AwsIcon icon={ICONS.alarm} size={18} />
              </span>
              <span className="row-text">
                <span className="row-title">{name}</span>
              </span>
              <span className="row-meta">
                <Status
                  tone={
                    state === "ALARM"
                      ? "bad"
                      : state === "OK"
                        ? "good"
                        : "neutral"
                  }
                >
                  {state ?? "unknown"}
                </Status>
              </span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

/** "SOURCE '/app/api' | fields ...": the groups and the query of a log widget. */
function logQuery(query: string) {
  const [source, ...rest] = query.split("|");
  const groups = [...source.matchAll(/'([^']+)'/g)].map((m) => m[1]);
  return { groups, query: groups.length ? rest.join("|").trim() : query };
}

const NAME_HINT: Rule = { ...PutMetricAlarm.Namespace, required: true };

export default async function DashboardPage({ searchParams }: Props) {
  const { name = "", range = "3h" } = await searchParams;
  const back = { href: "/dashboards", label: "Dashboards" };
  const data = await load(async () =>
    (await cloudwatch()).send(new GetDashboardCommand({ DashboardName: name })),
  );
  if (!data.ok) {
    return (
      <Page title={name} icon="service/AmazonCloudWatch" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  let widgets: Widget[] = [];
  try {
    widgets =
      (JSON.parse(data.value.DashboardBody ?? "{}") as { widgets?: Widget[] })
        .widgets ?? [];
  } catch {
    // MWS validates bodies; nothing to draw from a broken one
  }
  const start = RANGES.find(([k]) => k === range)?.[1] ?? "-PT3H";
  const alarmArns = widgets.flatMap((w) =>
    w.type === "alarm" ? ((w.properties?.alarms as string[]) ?? []) : [],
  );
  const [states, options, alarms] = await Promise.all([
    alarmArns.length
      ? load(async () => {
          const out = await (
            await cloudwatch()
          ).send(
            new DescribeAlarmsCommand({
              AlarmNames: [...new Set(alarmArns.map(arnName))].slice(0, 100),
              AlarmTypes: ["MetricAlarm", "CompositeAlarm", "LogAlarm"],
            }),
          );
          return new Map(
            [
              ...(out.MetricAlarms ?? []),
              ...(out.CompositeAlarms ?? []),
              ...(out.LogAlarms ?? []),
            ].map((a) => [a.AlarmName!, a.StateValue ?? ""]),
          );
        })
      : Promise.resolve({
          ok: true as const,
          value: new Map<string, string>(),
        }),
    formOptions(),
    load(listAlarms),
  ]);
  const base = `/dashboards/dashboard?${new URLSearchParams({ name })}`;
  // Widgets in reading order: by row, then column.
  const ordered = widgets
    .map((w, i) => ({ w, i }))
    .sort((a, b) => (a.w.y ?? 0) - (b.w.y ?? 0) || (a.w.x ?? 0) - (b.w.x ?? 0));
  return (
    <Page
      title={name}
      icon="service/AmazonCloudWatch"
      back={back}
      subtitle={data.value.DashboardArn}
      actions={
        <>
          <Sheet
            title="Add metric widget"
            label="Add metric widget"
            icon={<ChartLine size={16} />}
            testId="add-metric-widget"
          >
            <ActionForm
              action={addMetricWidget.bind(null, name)}
              submit="Add"
              testId="add-metric-widget"
            >
              <Field label="Title" rule={{ maxLength: 255 }}>
                <input name="title" />
              </Field>
              <Field
                label="Namespace"
                rule={NAME_HINT}
                known={options.namespaces}
              >
                <input name="namespace" list="widget-namespaces" />
              </Field>
              <datalist id="widget-namespaces">
                {options.namespaces.map((n) => (
                  <option key={n} value={n} />
                ))}
              </datalist>
              <Field
                label="Metric"
                rule={{ ...PutMetricAlarm.MetricName, required: true }}
                known={options.names}
              >
                <input name="metric" list="widget-metrics" />
              </Field>
              <datalist id="widget-metrics">
                {options.names.map((n) => (
                  <option key={n} value={n} />
                ))}
              </datalist>
              <Field
                label="Dimensions"
                rule={{ format: "pairs", maxLength: 4096 }}
                known={options.dims}
              >
                <textarea name="dims" rows={2} placeholder="QueueName=orders" />
              </Field>
              <div className="form-grid">
                <Field label="Statistic" rule={{ type: "string" }}>
                  <select name="stat" defaultValue="Average">
                    {STATISTICS.map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </Field>
                <Field
                  label="Period (s)"
                  rule={{ ...PutMetricAlarm.Period, unit: "seconds" }}
                >
                  <input name="period" type="number" defaultValue={300} />
                </Field>
                <Field
                  label="View"
                  rule={{ enum: ["timeSeries", "singleValue", "bar", "pie"] }}
                >
                  <select name="view" defaultValue="timeSeries">
                    <option value="timeSeries">Line</option>
                    <option value="singleValue">Number</option>
                    <option value="bar">Bar</option>
                    <option value="pie">Pie</option>
                  </select>
                </Field>
                <Field
                  label="Width"
                  rule={{ type: "integer", min: 1, max: 24 }}
                >
                  <input name="width" type="number" defaultValue={12} />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
          <Sheet
            title="Add text widget"
            label="Add text widget"
            icon={<Type size={16} />}
            testId="add-text-widget"
          >
            <ActionForm
              action={addTextWidget.bind(null, name)}
              submit="Add"
              testId="add-text-widget"
            >
              <Field
                label="Markdown"
                rule={{ required: true, maxLength: 10000 }}
              >
                <textarea name="markdown" rows={4} />
              </Field>
              <Field label="Width" rule={{ type: "integer", min: 1, max: 24 }}>
                <input name="width" type="number" defaultValue={24} />
              </Field>
            </ActionForm>
          </Sheet>
          {alarms.ok && alarms.value.length > 0 && (
            <Sheet
              title="Add alarm status widget"
              label="Add alarm widget"
              icon={<BellRing size={16} />}
              testId="add-alarm-widget"
            >
              <ActionForm
                action={addAlarmWidget.bind(null, name)}
                submit="Add"
                testId="add-alarm-widget"
              >
                <Field label="Title" rule={{ maxLength: 255 }}>
                  <input name="title" defaultValue="Alarms" />
                </Field>
                <Field label="Alarms" rule={{ required: true }}>
                  <select
                    name="alarms"
                    multiple
                    size={Math.min(8, alarms.value.length)}
                  >
                    {alarms.value.map((a) => (
                      <option key={a.AlarmArn} value={a.AlarmArn}>
                        {a.AlarmName}
                      </option>
                    ))}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          )}
          <Sheet
            title="Edit source"
            label="Edit source"
            icon={<Code size={16} />}
            testId="dashboard-source"
          >
            <ActionForm
              action={saveSource.bind(null, name)}
              submit="Save"
              testId="dashboard-source"
            >
              <Field
                label="Source"
                rule={{ ...PutDashboard.DashboardBody, format: "json" }}
              >
                <textarea
                  name="body"
                  rows={18}
                  className="code-editor"
                  defaultValue={JSON.stringify(
                    JSON.parse(data.value.DashboardBody || '{"widgets":[]}'),
                    null,
                    2,
                  )}
                />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={deleteDashboard.bind(null, name, true)}
            submit="Delete dashboard"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${name}?`}
            testId="delete-dashboard"
          />
        </>
      }
    >
      <Segments
        label="Time range"
        items={RANGES.map(([k]) => ({
          label: k,
          href: `${base}&range=${k}`,
          active: k === range,
        }))}
      />
      {ordered.length === 0 ? (
        <Empty icon="service/AmazonCloudWatch" />
      ) : (
        <div
          style={{ display: "flex", flexWrap: "wrap", gap: 12 }}
          aria-label="Widgets"
        >
          {ordered.map(({ w, i }) => {
            const props = w.properties ?? {};
            const title =
              typeof props.title === "string" ? props.title : undefined;
            let content;
            if (w.type === "metric")
              content = <MetricWidget properties={props} start={start} />;
            else if (w.type === "text")
              content = (
                <div style={{ whiteSpace: "pre-wrap" }}>
                  {String(props.markdown ?? "")}
                </div>
              );
            else if (w.type === "alarm")
              content = (
                <AlarmWidget
                  arns={(props.alarms as string[]) ?? []}
                  states={states.ok ? states.value : new Map()}
                />
              );
            else if (w.type === "log") {
              const q = logQuery(String(props.query ?? ""));
              content = (
                <Link
                  href={`/logs/insights?${new URLSearchParams({ q: q.query, groups: q.groups.join(",") })}`}
                >
                  <FileSearch size={14} aria-hidden /> <code>{q.query}</code>
                </Link>
              );
            } else content = <span className="muted">{w.type}</span>;
            return (
              <div
                key={i}
                style={{
                  flex: `1 1 calc(${((w.width ?? 6) / 24) * 100}% - 12px)`,
                  minWidth: 280,
                }}
                data-testid="widget"
              >
                <Section
                  title={title}
                  actions={
                    <ActionForm
                      action={removeWidget.bind(null, name, i)}
                      submit={`Remove ${title ?? `widget ${i + 1}`}`}
                      icon={<X size={14} />}
                      confirm="Remove this widget?"
                    />
                  }
                >
                  {content}
                </Section>
              </div>
            );
          })}
        </div>
      )}
    </Page>
  );
}
