import {
  DescribeAlarmsForMetricCommand,
  DescribeAnomalyDetectorsCommand,
  GetMetricDataCommand,
  ListMetricsCommand,
  type Dimension,
} from "@aws-sdk/client-cloudwatch";
import { search } from "@mws-dashboard/ai";
import { all, load, mws } from "@mws-dashboard/aws";
import {
  ActionForm,
  AwsIcon,
  Empty,
  ErrorNotice,
  Field,
  List,
  Metric,
  Metrics,
  Page,
  Section,
  Segments,
  Sheet,
  Status,
  Table,
} from "@mws-dashboard/ui";
import { PutMetricData } from "@mws-dashboard/ui/model/cloudwatch";
import {
  CircleOff,
  LayoutDashboard,
  Radar,
  Upload,
  Users,
  Waypoints,
} from "lucide-react";
import Link from "next/link";
import type { Metadata } from "next";

import { metricRule } from "../../lib/alarms";
import {
  ALARM_TONE,
  ICONS,
  alarmHref,
  cloudwatch,
  dimsText,
  metricHref,
  sourceIcon,
} from "../../lib/clients";
import {
  deleteAnomalyDetector,
  putAnomalyDetector,
  putMetricData,
} from "./actions";
import { LineChart } from "./chart";

export const metadata: Metadata = { title: "Metrics" };

/** "AWS/SQS" reads as "SQS" next to the SQS icon; custom namespaces stay whole. */
const nsLabel = (ns: string) => ns.replace(/^AWS\//, "");

type Props = {
  searchParams: Promise<{
    ns?: string;
    metric?: string;
    dims?: string;
    q?: string;
    stat?: string;
    period?: string;
    range?: string;
  }>;
};

const RANGES: [string, number][] = [
  ["1h", 3600],
  ["3h", 3 * 3600],
  ["12h", 12 * 3600],
  ["1d", 86400],
  ["1w", 7 * 86400],
];
const PERIODS: [number, string][] = [
  [60, "1 min"],
  [300, "5 min"],
  [3600, "1 h"],
];
const STATS = [
  "Average",
  "Sum",
  "Maximum",
  "Minimum",
  "SampleCount",
  "p99",
  "p90",
  "p50",
];

async function Series({
  ns,
  metric,
  dims,
  stat,
  period,
  range,
  href,
}: {
  ns: string;
  metric: string;
  dims: Dimension[];
  stat: string;
  period: number;
  range: number;
  href: (p: Record<string, string>) => string;
}) {
  // At most 1,440 datapoints per series: widen the period for long ranges.
  const step = Math.max(period, Math.ceil(range / 1440 / 60) * 60);
  const data = await load(async () => {
    const clock = await mws<{ now: string }>("/_mws/clock");
    const end = new Date(clock.now);
    const c = await cloudwatch();
    const detectors = await c
      .send(
        new DescribeAnomalyDetectorsCommand({
          Namespace: ns,
          MetricName: metric,
          Dimensions: dims,
        }),
      )
      .then(
        (r) => r.AnomalyDetectors ?? [],
        () => [],
      );
    const detector = detectors.find(
      (d) => (d.SingleMetricAnomalyDetector?.Stat ?? d.Stat) === stat,
    );
    const stats = [...new Set([stat, "Sum", "Average", "Maximum"])];
    const [out, alarms] = await Promise.all([
      c.send(
        new GetMetricDataCommand({
          StartTime: new Date(end.getTime() - range * 1000),
          EndTime: new Date(end.getTime() + 60_000),
          MetricDataQueries: [
            ...stats.map((s, i) => ({
              Id: `q${i}`,
              Label: s,
              MetricStat: {
                Metric: { Namespace: ns, MetricName: metric, Dimensions: dims },
                Period: step,
                Stat: s,
              },
            })),
            ...(detector
              ? [
                  {
                    Id: "band",
                    Label: "band",
                    Expression: "ANOMALY_DETECTION_BAND(q0, 2)",
                  },
                ]
              : []),
          ],
        }),
      ),
      c
        .send(
          new DescribeAlarmsForMetricCommand({
            Namespace: ns,
            MetricName: metric,
            Dimensions: dims,
          }),
        )
        .then((r) => r.MetricAlarms ?? []),
    ]);
    return { results: out.MetricDataResults ?? [], alarms, detector };
  });
  if (!data.ok) return <ErrorNotice error={data.error} />;
  const series = (label: string) => {
    const r = data.value.results.find((d) => d.Label === label);
    return (r?.Timestamps ?? [])
      .map((t, i) => ({ t, v: r!.Values![i] }))
      .sort((a, b) => a.t.getTime() - b.t.getTime());
  };
  const shown = series(stat);
  const sum = series("Sum");
  const avg = series("Average");
  const max = series("Maximum");
  const total = sum.reduce((n, p) => n + p.v, 0);
  const alarms = data.value.alarms;
  const detector = data.value.detector;
  // The band comes back as two series of one id: the low and the high edge.
  const bandRows = data.value.results.filter(
    (r) => r.Id === "band" || r.Id?.startsWith("band"),
  );
  const band =
    bandRows.length >= 2
      ? (bandRows[0].Timestamps ?? []).map((t, i) => {
          const a = bandRows[0].Values![i];
          const b =
            bandRows[1].Values?.[
              bandRows[1].Timestamps!.findIndex(
                (x) => x.getTime() === t.getTime(),
              )
            ] ?? a;
          return { t, lo: Math.min(a, b), hi: Math.max(a, b) };
        })
      : undefined;
  const dimsList = dims.map((d) => ({ Name: d.Name!, Value: d.Value! }));
  const rangeLabel = RANGES.find(([, s]) => s === range)?.[0] ?? "";
  return (
    <>
      <div
        className="form-row"
        style={{ alignItems: "center", flexWrap: "wrap" }}
      >
        <Segments
          label="Statistic"
          items={STATS.map((s) => ({
            label: s,
            href: href({ stat: s }),
            active: s === stat,
          }))}
        />
        <Segments
          label="Period"
          items={PERIODS.map(([p, l]) => ({
            label: l,
            href: href({ period: String(p) }),
            active: p === period,
          }))}
        />
        <Segments
          label="Range"
          items={RANGES.map(([k, s]) => ({
            label: k,
            href: href({ range: k }),
            active: s === range,
          }))}
        />
        {detector ? (
          <ActionForm
            action={deleteAnomalyDetector.bind(
              null,
              ns,
              metric,
              dimsList,
              stat,
            )}
            submit="Turn off anomaly detection"
            icon={<CircleOff size={15} />}
            confirm="Delete this anomaly detector?"
          />
        ) : (
          <ActionForm
            action={putAnomalyDetector.bind(null, ns, metric, dimsList, stat)}
            submit="Turn on anomaly detection"
            icon={<Radar size={15} />}
          />
        )}
        {detector?.StateValue && (
          <Status tone={detector.StateValue === "TRAINED" ? "good" : "warn"}>
            {detector.StateValue.toLowerCase().replace("_", " ")}
          </Status>
        )}
      </div>
      <Section>
        {shown.length === 0 ? (
          <Empty icon={ICONS.metrics} />
        ) : (
          <>
            {sum.some((p) => p.v !== 0) && (
              <Metrics>
                <Metric
                  label={`Sum · ${rangeLabel}`}
                  value={+total.toFixed(2)}
                />
                <Metric label="Peak" value={Math.max(...max.map((p) => p.v))} />
                <Metric
                  label="Average"
                  value={
                    +(
                      avg.reduce((n, p) => n + p.v, 0) / Math.max(avg.length, 1)
                    ).toFixed(2)
                  }
                />
              </Metrics>
            )}
            <LineChart
              points={shown}
              label="Metric chart"
              band={band}
              threshold={
                alarms.find(
                  (a) =>
                    a.Threshold !== undefined &&
                    (a.Statistic ?? a.ExtendedStatistic) === stat,
                )?.Threshold
              }
            />
            <details>
              <summary className="muted">Datapoints</summary>
              <Table
                label="Datapoints"
                rows={(sum.length ? sum : shown).slice(-30).reverse()}
                rowKey={(p) => p.t.toISOString()}
                columns={[
                  {
                    header: "Time",
                    cell: (p) =>
                      p.t
                        .toISOString()
                        .slice(range > 86400 ? 5 : 11, 16)
                        .replace("T", " "),
                  },
                  {
                    header: "Sum",
                    className: "num",
                    cell: (p) =>
                      sum.find((a) => a.t.getTime() === p.t.getTime())?.v ??
                      "—",
                  },
                  {
                    header: "Average",
                    className: "num",
                    cell: (p) =>
                      avg.find((a) => a.t.getTime() === p.t.getTime())?.v ??
                      "—",
                  },
                  {
                    header: "Maximum",
                    className: "num",
                    cell: (p) =>
                      max.find((a) => a.t.getTime() === p.t.getTime())?.v ??
                      "—",
                  },
                ]}
              />
            </details>
          </>
        )}
      </Section>
      <Section title="Alarms" count={alarms.length} plain>
        <List
          label="Alarms on this metric"
          empty={<Empty icon={ICONS.alarm} />}
          rows={alarms.map((a) => ({
            key: a.AlarmArn!,
            icon: <AwsIcon icon={ICONS.alarm} size={20} />,
            title: a.AlarmName,
            subtitle: metricRule(a),
            href: alarmHref(a.AlarmName!),
            meta: (
              <Status tone={ALARM_TONE[a.StateValue ?? ""] ?? "neutral"}>
                {a.StateValue?.toLowerCase().replace("_", " ") ?? ""}
              </Status>
            ),
          }))}
        />
      </Section>
    </>
  );
}

const METRIC_DATA = PutMetricData.MetricData.item!.fields!;

export default async function MetricsPage({ searchParams }: Props) {
  const {
    ns,
    metric,
    dims,
    q = "",
    stat = "Average",
    period,
    range,
  } = await searchParams;
  const client = await cloudwatch();
  const metrics = await load(() =>
    all(
      (NextToken) => client.send(new ListMetricsCommand({ NextToken })),
      (r) => r.Metrics,
      (r) => r.NextToken,
    ),
  );
  if (!metrics.ok) {
    return (
      <Page title="Metrics">
        <ErrorNotice error={metrics.error} />
      </Page>
    );
  }
  const namespaces = [...new Set(metrics.value.map((m) => m.Namespace!))].sort(
    (a, b) =>
      Number(a.startsWith("AWS/")) - Number(b.startsWith("AWS/")) ||
      a.localeCompare(b),
  );
  const current =
    ns && namespaces.includes(ns) ? ns : q ? undefined : namespaces[0];
  let selectedDims: Dimension[] = [];
  try {
    selectedDims = dims ? (JSON.parse(dims) as Dimension[]) : [];
  } catch {
    // ignore a malformed link
  }
  const publish = (
    <Sheet
      title="Publish metric data"
      label="Publish metric data"
      icon={<Upload size={16} />}
      testId="put-metric-data"
    >
      <ActionForm
        action={putMetricData}
        submit="Publish"
        testId="put-metric-data"
      >
        <Field
          label="Namespace"
          rule={{ ...PutMetricData.Namespace, reserved: ["AWS/"] }}
          known={namespaces}
        >
          <input
            name="namespace"
            list="put-namespaces"
            defaultValue={current && !current.startsWith("AWS/") ? current : ""}
          />
        </Field>
        <datalist id="put-namespaces">
          {namespaces
            .filter((n) => !n.startsWith("AWS/"))
            .map((n) => (
              <option key={n} value={n} />
            ))}
        </datalist>
        <Field label="Metric" rule={METRIC_DATA.MetricName}>
          <input name="metric" defaultValue={metric} />
        </Field>
        <Field label="Dimensions" rule={{ format: "pairs", maxLength: 4096 }}>
          <textarea
            name="dims"
            rows={2}
            placeholder="QueueName=orders"
            defaultValue={dimsText(selectedDims).replace(/, /g, "\n")}
          />
        </Field>
        <div className="form-grid">
          <Field label="Value" rule={{ ...METRIC_DATA.Value, required: true }}>
            <input name="value" type="number" step="any" defaultValue={1} />
          </Field>
          <Field label="Unit" rule={METRIC_DATA.Unit}>
            <select name="unit" defaultValue="None">
              {METRIC_DATA.Unit.enum!.map((u) => (
                <option key={u}>{u}</option>
              ))}
            </select>
          </Field>
          <Field label="Count" rule={{ type: "integer", min: 1, max: 1000 }}>
            <input name="count" type="number" defaultValue={1} />
          </Field>
        </div>
      </ActionForm>
    </Sheet>
  );
  if (metric && current) {
    const params = {
      ns: current,
      metric,
      dims: JSON.stringify(selectedDims),
      stat,
      ...(period ? { period } : {}),
      ...(range ? { range } : {}),
    };
    const href = (p: Record<string, string>) =>
      `/metrics?${new URLSearchParams({ ...params, ...p })}`;
    return (
      <Page
        title={metric}
        icon={sourceIcon(current) ?? ICONS.metrics}
        back={{
          href: `/metrics?ns=${encodeURIComponent(current)}`,
          label: nsLabel(current),
        }}
        subtitle={dimsText(selectedDims) || undefined}
        actions={publish}
      >
        <Series
          ns={current}
          metric={metric}
          dims={selectedDims}
          stat={stat}
          period={Number(period) || 60}
          range={RANGES.find(([k]) => k === range)?.[1] ?? 3 * 3600}
          href={href}
        />
      </Page>
    );
  }
  const docs = metrics.value.map((m) => ({
    ...m,
    text: `${m.Namespace} ${m.MetricName} ${dimsText(m.Dimensions)}`,
  }));
  const rows = q
    ? await search(q, docs, 40)
    : docs.filter((m) => m.Namespace === current);
  return (
    <Page
      title="Metrics"
      actions={
        <>
          {publish}
          <Link
            className="icon-button plain"
            href="/metrics/streams"
            aria-label="Metric streams"
            title="Metric streams"
          >
            <Waypoints size={16} aria-hidden />
          </Link>
          <Link
            className="icon-button plain"
            href="/metrics/contributors"
            aria-label="Contributor Insights"
            title="Contributor Insights"
          >
            <Users size={16} aria-hidden />
          </Link>
          <Link
            className="icon-button plain"
            href="/dashboards"
            aria-label="Dashboards"
            title="Dashboards"
          >
            <LayoutDashboard size={16} aria-hidden />
          </Link>
        </>
      }
    >
      {namespaces.length === 0 ? (
        <Empty icon={ICONS.metrics} />
      ) : (
        <>
          <form className="search-page-form" action="/metrics">
            <input
              name="q"
              defaultValue={q}
              placeholder="Find a metric"
              aria-label="Find a metric"
            />
          </form>
          <nav className="tiles compact" aria-label="Namespaces">
            {namespaces.map((n) => (
              <Link
                key={n}
                href={`/metrics?ns=${encodeURIComponent(n)}`}
                className={n === current ? "tile active" : "tile"}
                aria-current={n === current ? "page" : undefined}
              >
                <AwsIcon icon={sourceIcon(n) ?? ICONS.metrics} size={28} />
                <span className="tile-name">{nsLabel(n)}</span>
                <span className="muted">
                  {metrics.value.filter((m) => m.Namespace === n).length}
                </span>
              </Link>
            ))}
          </nav>
          <Section
            title={q ? undefined : current && nsLabel(current)}
            count={rows.length}
            plain
          >
            <List
              label="Metrics"
              rows={rows.map((m) => ({
                key: `${m.Namespace}|${m.MetricName}|${dimsText(m.Dimensions)}`,
                icon: (
                  <AwsIcon
                    icon={sourceIcon(m.Namespace!) ?? ICONS.metrics}
                    size={20}
                  />
                ),
                title: m.MetricName,
                subtitle:
                  [q ? m.Namespace : null, dimsText(m.Dimensions)]
                    .filter(Boolean)
                    .join(" · ") || undefined,
                href: metricHref(m.Namespace!, m.MetricName!, m.Dimensions),
              }))}
            />
          </Section>
        </>
      )}
    </Page>
  );
}
