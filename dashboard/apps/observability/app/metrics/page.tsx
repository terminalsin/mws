import { GetMetricDataCommand, ListMetricsCommand, type Dimension } from "@aws-sdk/client-cloudwatch";
import { collect, load, mws, when } from "@mws-dashboard/aws";
import { Empty, ErrorNotice, PageHeader, Section, Table, Tabs } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { cloudwatch } from "../../lib/clients";

export const metadata: Metadata = { title: "Metrics" };

type Props = { searchParams: Promise<{ ns?: string; metric?: string; dims?: string }> };

const dimsText = (dims: Dimension[] | undefined) => (dims ?? []).map((d) => `${d.Name}=${d.Value}`).join(", ");

function metricHref(ns: string, name: string, dims: Dimension[] | undefined) {
  return `/metrics?${new URLSearchParams({ ns, metric: name, dims: JSON.stringify(dims ?? []) })}`;
}

/** A small line chart of one series; no client JavaScript needed. */
function Sparkline({ points }: { points: { t: Date; v: number }[] }) {
  if (points.length === 0) return <Empty>No datapoints in the last three hours.</Empty>;
  const w = 720;
  const h = 160;
  const pad = 24;
  const ts = points.map((p) => p.t.getTime());
  const vs = points.map((p) => p.v);
  const [t0, t1] = [Math.min(...ts), Math.max(...ts)];
  const [v0, v1] = [Math.min(0, ...vs), Math.max(...vs)];
  const x = (t: number) => pad + ((t - t0) / Math.max(t1 - t0, 1)) * (w - 2 * pad);
  const y = (v: number) => h - pad - ((v - v0) / Math.max(v1 - v0, 1e-9)) * (h - 2 * pad);
  const path = points.map((p, i) => `${i ? "L" : "M"}${x(p.t.getTime()).toFixed(1)},${y(p.v).toFixed(1)}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" role="img" aria-label="Metric chart" style={{ maxWidth: w }}>
      <line x1={pad} x2={w - pad} y1={h - pad} y2={h - pad} stroke="var(--border)" />
      <text x={pad} y={14} fontSize="11" fill="var(--muted)">
        max {v1}
      </text>
      <path d={path} fill="none" stroke="var(--accent)" strokeWidth="2" />
      {points.map((p, i) => (
        <circle key={i} cx={x(p.t.getTime())} cy={y(p.v)} r="2.5" fill="var(--accent)" />
      ))}
    </svg>
  );
}

async function Series({ ns, metric, dims }: { ns: string; metric: string; dims: Dimension[] }) {
  const data = await load(async () => {
    const clock = await mws<{ now: string }>("/_mws/clock");
    const end = new Date(clock.now);
    const out = await (await cloudwatch()).send(
      new GetMetricDataCommand({
        StartTime: new Date(end.getTime() - 3 * 3600_000),
        EndTime: new Date(end.getTime() + 60_000),
        MetricDataQueries: ["Sum", "Average", "Maximum"].map((stat) => ({
          Id: stat.toLowerCase(),
          MetricStat: { Metric: { Namespace: ns, MetricName: metric, Dimensions: dims }, Period: 60, Stat: stat },
        })),
      }),
    );
    return out.MetricDataResults ?? [];
  });
  if (!data.ok) return <ErrorNotice error={data.error} />;
  const series = (id: string) => {
    const r = data.value.find((d) => d.Id === id);
    return (r?.Timestamps ?? []).map((t, i) => ({ t, v: r!.Values![i] })).sort((a, b) => a.t.getTime() - b.t.getTime());
  };
  const sum = series("sum");
  const avg = series("average");
  const max = series("maximum");
  return (
    <Section title={`${metric}${dims.length ? ` (${dimsText(dims)})` : ""}: sum per minute, last 3 hours`}>
      <Sparkline points={sum} />
      <Table
        label="Datapoints"
        rows={sum.slice(-20).reverse()}
        rowKey={(p) => p.t.toISOString()}
        columns={[
          { header: "Minute", cell: (p) => when(p.t) },
          { header: "Sum", className: "num", cell: (p) => p.v },
          { header: "Average", className: "num", cell: (p) => avg.find((a) => a.t.getTime() === p.t.getTime())?.v ?? "—" },
          { header: "Maximum", className: "num", cell: (p) => max.find((a) => a.t.getTime() === p.t.getTime())?.v ?? "—" },
        ]}
      />
    </Section>
  );
}

export default async function Metrics({ searchParams }: Props) {
  const { ns, metric, dims } = await searchParams;
  const client = await cloudwatch();
  const metrics = await load(() =>
    collect(
      (NextToken) => client.send(new ListMetricsCommand({ NextToken })),
      (r) => r.Metrics,
      (r) => r.NextToken,
      5000,
    ),
  );
  if (!metrics.ok) {
    return (
      <>
        <PageHeader title="Metrics" />
        <ErrorNotice error={metrics.error} />
      </>
    );
  }
  const namespaces = [...new Set(metrics.value.map((m) => m.Namespace!))].sort();
  const current = ns && namespaces.includes(ns) ? ns : namespaces[0];
  const rows = metrics.value.filter((m) => m.Namespace === current);
  let selectedDims: Dimension[] = [];
  try {
    selectedDims = dims ? (JSON.parse(dims) as Dimension[]) : [];
  } catch {
    // ignore a malformed link
  }
  return (
    <>
      <PageHeader title="Metrics" description="CloudWatch metrics in the selected region: what your code publishes and what MWS services emit." />
      {namespaces.length === 0 ? (
        <Empty>No metrics yet. Publish one with PutMetricData, or use a service that emits them (SQS, Lambda, ...).</Empty>
      ) : (
        <>
          <Tabs
            items={namespaces.map((n) => ({
              label: n,
              href: `/metrics?ns=${encodeURIComponent(n)}`,
              active: n === current,
              count: metrics.value.filter((m) => m.Namespace === n).length,
            }))}
          />
          {metric && current && <Series ns={current} metric={metric} dims={selectedDims} />}
          <Section title={current}>
            <Table
              label="Metrics"
              rows={rows}
              rowKey={(m) => `${m.MetricName}|${dimsText(m.Dimensions)}`}
              columns={[
                { header: "Metric", cell: (m) => <Link href={metricHref(current!, m.MetricName!, m.Dimensions)}>{m.MetricName}</Link> },
                { header: "Dimensions", className: "wrap", cell: (m) => <code>{dimsText(m.Dimensions) || "none"}</code> },
              ]}
            />
          </Section>
        </>
      )}
    </>
  );
}
