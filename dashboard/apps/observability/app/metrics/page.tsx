import { GetMetricDataCommand, ListMetricsCommand, type Dimension } from "@aws-sdk/client-cloudwatch";
import { search } from "@mws-dashboard/ai";
import { collect, load, mws } from "@mws-dashboard/aws";
import { AwsIcon, Empty, ErrorNotice, List, Metric, Metrics, Page, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, cloudwatch, dimsText, metricHref, sourceIcon } from "../../lib/clients";
import { LineChart } from "./chart";

export const metadata: Metadata = { title: "Metrics" };

/** "AWS/SQS" reads as "SQS" next to the SQS icon; custom namespaces stay whole. */
const nsLabel = (ns: string) => ns.replace(/^AWS\//, "");

type Props = { searchParams: Promise<{ ns?: string; metric?: string; dims?: string; q?: string }> };

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
  const total = sum.reduce((n, p) => n + p.v, 0);
  return (
    <Section>
      {sum.length === 0 ? (
        <Empty icon={ICONS.metrics} />
      ) : (
        <>
          {sum.some((p) => p.v !== 0) && <Metrics>
            <Metric label="Sum · 3 h" value={+total.toFixed(2)} />
            <Metric label="Peak minute" value={Math.max(...max.map((p) => p.v))} />
            <Metric label="Average" value={+(avg.reduce((n, p) => n + p.v, 0) / Math.max(avg.length, 1)).toFixed(2)} />
          </Metrics>}
          <LineChart points={sum} label="Metric chart" />
          <details>
            <summary className="muted">Datapoints</summary>
            <Table
              label="Datapoints"
              rows={sum.slice(-30).reverse()}
              rowKey={(p) => p.t.toISOString()}
              columns={[
                { header: "Minute", cell: (p) => p.t.toISOString().slice(11, 16) },
                { header: "Sum", className: "num", cell: (p) => p.v },
                { header: "Average", className: "num", cell: (p) => avg.find((a) => a.t.getTime() === p.t.getTime())?.v ?? "—" },
                { header: "Maximum", className: "num", cell: (p) => max.find((a) => a.t.getTime() === p.t.getTime())?.v ?? "—" },
              ]}
            />
          </details>
        </>
      )}
    </Section>
  );
}

export default async function MetricsPage({ searchParams }: Props) {
  const { ns, metric, dims, q = "" } = await searchParams;
  const client = await cloudwatch();
  const metrics = await load(() => collect((NextToken) => client.send(new ListMetricsCommand({ NextToken })), (r) => r.Metrics, (r) => r.NextToken, 5000));
  if (!metrics.ok) {
    return (
      <Page title="Metrics">
        <ErrorNotice error={metrics.error} />
      </Page>
    );
  }
  const namespaces = [...new Set(metrics.value.map((m) => m.Namespace!))].sort((a, b) => Number(a.startsWith("AWS/")) - Number(b.startsWith("AWS/")) || a.localeCompare(b));
  const current = ns && namespaces.includes(ns) ? ns : q ? undefined : namespaces[0];
  let selectedDims: Dimension[] = [];
  try {
    selectedDims = dims ? (JSON.parse(dims) as Dimension[]) : [];
  } catch {
    // ignore a malformed link
  }
  if (metric && current) {
    return (
      <Page title={metric} icon={sourceIcon(current) ?? ICONS.metrics} back={{ href: `/metrics?ns=${encodeURIComponent(current)}`, label: nsLabel(current) }} subtitle={dimsText(selectedDims) || undefined}>
        <Series ns={current} metric={metric} dims={selectedDims} />
      </Page>
    );
  }
  const docs = metrics.value.map((m) => ({ ...m, text: `${m.Namespace} ${m.MetricName} ${dimsText(m.Dimensions)}` }));
  const rows = q ? await search(q, docs, 40) : docs.filter((m) => m.Namespace === current);
  return (
    <Page title="Metrics">
      {namespaces.length === 0 ? (
        <Empty icon={ICONS.metrics} />
      ) : (
        <>
          <form className="search-page-form" action="/observability/metrics">
            <input name="q" defaultValue={q} placeholder="Find a metric" aria-label="Find a metric" />
          </form>
          <nav className="tiles compact" aria-label="Namespaces">
            {namespaces.map((n) => (
              <Link key={n} href={`/metrics?ns=${encodeURIComponent(n)}`} className={n === current ? "tile active" : "tile"} aria-current={n === current ? "page" : undefined}>
                <AwsIcon icon={sourceIcon(n) ?? ICONS.metrics} size={28} />
                <span className="tile-name">{nsLabel(n)}</span>
                <span className="muted">{metrics.value.filter((m) => m.Namespace === n).length}</span>
              </Link>
            ))}
          </nav>
          <Section title={q ? undefined : current && nsLabel(current)} count={rows.length} plain>
            <List
              label="Metrics"
              rows={rows.map((m) => ({
                key: `${m.Namespace}|${m.MetricName}|${dimsText(m.Dimensions)}`,
                icon: <AwsIcon icon={sourceIcon(m.Namespace!) ?? ICONS.metrics} size={20} />,
                title: m.MetricName,
                subtitle: [q ? m.Namespace : null, dimsText(m.Dimensions)].filter(Boolean).join(" · ") || undefined,
                href: metricHref(m.Namespace!, m.MetricName!, m.Dimensions),
              }))}
            />
          </Section>
        </>
      )}
    </Page>
  );
}
