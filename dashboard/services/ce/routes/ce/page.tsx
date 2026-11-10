import {
  GetCostAndUsageCommand,
  GetCostForecastCommand,
  GetDimensionValuesCommand,
  GetTagsCommand,
  ListCostCategoryDefinitionsCommand,
  type ResultByTime,
} from "@aws-sdk/client-cost-explorer";
import { all, describeError, load } from "@mws-dashboard/aws";
import { AwsIcon, Empty, ErrorNotice, Field, Metric, Metrics, Page, Section, SERVICES, Table } from "@mws-dashboard/ui";
import { Filter, Tags } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ce } from "../../lib/clients";
import { addDays, day, money, monthStart, mwsNow } from "../../lib/clock";
import { DIMENSIONS, filterOf, groupBy, label, METRICS, parseQuery, period, split, type Query } from "../../lib/query";

export const metadata: Metadata = { title: "Cost Explorer" };


/** AWS's billing names ("Amazon Simple Storage Service") to catalog icons. */
const BILLING: [RegExp, string][] = [
  [/simple storage service/i, "s3"],
  [/simple queue service/i, "sqs"],
  [/simple notification service/i, "sns"],
  [/simple email service/i, "ses"],
  [/key management service/i, "kms"],
  [/cloudwatch events|eventbridge/i, "events"],
  [/cloudwatch/i, "cloudwatch"],
  [/elastic compute cloud|^ec2/i, "ec2"],
  [/relational database|rds/i, "rds"],
  [/elastic container registry/i, "ecr"],
  [/elastic container service/i, "ecs"],
  [/kubernetes/i, "eks"],
  [/elastic file system/i, "efs"],
  [/load balancing/i, "elb"],
  [/route ?53/i, "route53"],
  [/kinesis firehose|data firehose/i, "firehose"],
  [/kinesis/i, "kinesis"],
  [/cost explorer/i, "ce"],
  [/identity and access/i, "iam"],
];

function serviceIcon(name: string) {
  const id = BILLING.find(([re]) => re.test(name))?.[1];
  const n = name.toLowerCase().replace(/^(amazon|aws)\s*/, "");
  return SERVICES.find((s) => s.id === id || s.name.toLowerCase().replace(/^(amazon|aws)\s*/, "") === n)?.icon ?? ICONS.ce;
}

type Props = { searchParams: Promise<Record<string, string | string[] | undefined>> };

const USAGE = /Usage|Normalized/;

/** Why there is no forecast: too little history is expected, anything else is a problem. */
function forecastProblem(e: unknown): { expected: boolean; message: string } {
  const name = e instanceof Error ? e.name : "";
  return name === "DataUnavailableException" ? { expected: true, message: "Not enough cost history to forecast yet" } : { expected: false, message: describeError(e) };
}

function periodLabel(r: ResultByTime, q: Query) {
  const start = r.TimePeriod?.Start ?? "";
  if (q.granularity === "MONTHLY") return new Date(start.slice(0, 10) + "T00:00:00Z").toLocaleString("en-US", { month: "short", year: "2-digit", timeZone: "UTC" });
  if (q.granularity === "HOURLY") return start.slice(5, 16).replace("T", " ");
  return start.slice(5, 10);
}

export default async function CostExplorer({ searchParams }: Props) {
  const now = await mwsNow();
  const tomorrow = addDays(now, 1);
  const q = parseQuery(await searchParams, { start: day(monthStart(now, -5)), end: day(tomorrow) });
  const amount = (r: { Amount?: string } | undefined) => Number(r?.Amount ?? 0);
  const usage = USAGE.test(q.metric);
  const show = (n: number) => (usage ? n.toLocaleString("en-US", { maximumFractionDigits: 2 }) : money(n));
  const data = await load(async () => {
    const client = await ce();
    const suggestPeriod = { Start: day(addDays(now, -90)), End: day(tomorrow) };
    const filterKey = q.filter ? split(q.filter) : undefined;
    const [report, months, forecast, tags, categories, values] = await Promise.all([
      all(
        (NextPageToken) =>
          client.send(new GetCostAndUsageCommand({ TimePeriod: period(q), Granularity: q.granularity, Metrics: [q.metric], GroupBy: groupBy(q), Filter: filterOf(q), NextPageToken })),
        (r) => r.ResultsByTime,
        (r) => r.NextPageToken,
      ),
      client.send(new GetCostAndUsageCommand({ TimePeriod: { Start: day(monthStart(now, -1)), End: day(tomorrow) }, Granularity: "MONTHLY", Metrics: ["UnblendedCost"] })),
      client
        .send(new GetCostForecastCommand({ TimePeriod: { Start: day(tomorrow), End: day(monthStart(now, 1)) }, Granularity: "MONTHLY", Metric: "UNBLENDED_COST", PredictionIntervalLevel: 80 }))
        .then((f) => ({ ok: true as const, f }), (e: unknown) => ({ ok: false as const, ...forecastProblem(e) })),
      // Suggestions only: the form works without them.
      client.send(new GetTagsCommand({ TimePeriod: suggestPeriod })).then((r) => r.Tags ?? [], () => []),
      client.send(new ListCostCategoryDefinitionsCommand({})).then((r) => (r.CostCategoryReferences ?? []).map((c) => c.Name!), () => []),
      filterKey?.type === "DIMENSION"
        ? client.send(new GetDimensionValuesCommand({ TimePeriod: suggestPeriod, Dimension: filterKey.key as never })).then((r) => (r.DimensionValues ?? []).map((v) => v.Value!), () => [])
        : filterKey?.type === "TAG"
          ? client.send(new GetTagsCommand({ TimePeriod: suggestPeriod, TagKey: filterKey.key })).then((r) => r.Tags ?? [], () => [])
          : Promise.resolve([] as string[]),
    ]);
    return { report, months, forecast, tags, categories, values };
  });
  if (!data.ok) {
    return (
      <Page title="Cost and usage">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { report, forecast, tags, categories, values } = data.value;
  const monthly = data.value.months.ResultsByTime ?? [];
  const mtd = amount(monthly.at(-1)?.Total?.UnblendedCost);
  const last = monthly.length > 1 ? amount(monthly[0]?.Total?.UnblendedCost) : 0;
  const projected = forecast.ok ? mtd + amount(forecast.f.Total) : undefined;
  const bounds = forecast.ok ? forecast.f.ForecastResultsByTime?.[0] : undefined;

  // Each period's total and each group's amount per period.
  const total = (r: ResultByTime) => (r.Groups?.length ? r.Groups.reduce((n, g) => n + amount(g.Metrics?.[q.metric]), 0) : amount(r.Total?.[q.metric]));
  const periods = report.map((r) => ({ label: periodLabel(r, q), start: r.TimePeriod?.Start ?? "", value: total(r), estimated: r.Estimated }));
  const groupKeys = [...new Set(report.flatMap((r) => (r.Groups ?? []).map((g) => (g.Keys ?? []).join(" / "))))];
  const cell = (r: ResultByTime, key: string) => amount(r.Groups?.find((g) => (g.Keys ?? []).join(" / ") === key)?.Metrics?.[q.metric]);
  const groups = groupKeys
    .map((key) => ({ key, values: report.map((r) => cell(r, key)), total: report.reduce((n, r) => n + cell(r, key), 0) }))
    .filter((g) => g.total !== 0)
    .sort((a, b) => b.total - a.total);
  const latest = report.at(-1);
  const byLatest = latest ? groups.map((g) => ({ name: g.key, value: cell(latest, g.key) })).filter((g) => g.value > 0) : [];
  const max = Math.max(...periods.map((m) => m.value), 0.01);
  const top = byLatest[0]?.value ?? 1;
  const keyOptions = [
    ...Object.entries(DIMENSIONS).map(([k, l]) => ({ value: `DIMENSION:${k}`, label: l })),
    ...tags.map((t) => ({ value: `TAG:${t}`, label: `Tag: ${t}` })),
    ...categories.map((c) => ({ value: `COST_CATEGORY:${c}`, label: `Cost category: ${c}` })),
  ];
  // Keep a key from the URL even when no data mentions it yet.
  for (const k of [...q.groups, q.filter].filter(Boolean) as string[]) if (!keyOptions.some((o) => o.value === k)) keyOptions.push({ value: k, label: label(k) });
  const groupSelect = (i: number) => (
    <Field label={i === 0 ? "Group by" : "Then by"}>
      <select name="group" defaultValue={q.groups[i] ?? ""}>
        <option value="">None</option>
        {keyOptions.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </Field>
  );
  return (
    <Page
      title="Cost and usage"
      actions={
        <Link className="icon-button plain" href="/ce/tags" aria-label="Cost allocation tags" title="Cost allocation tags">
          <Tags size={16} />
        </Link>
      }
    >
      <Metrics>
        <Metric label="Month to date" value={money(mtd)} />
        {projected !== undefined && (
          <Metric
            label="Forecast this month"
            value={
              <span title={bounds?.PredictionIntervalLowerBound ? `80% interval: ${money(mtd + Number(bounds.PredictionIntervalLowerBound))} – ${money(mtd + Number(bounds.PredictionIntervalUpperBound))}` : undefined}>
                {money(projected)}
              </span>
            }
            tone={last && projected > last * 1.2 ? "warn" : undefined}
          />
        )}
        <Metric label="Last month" value={money(last)} />
      </Metrics>
      {!forecast.ok && (forecast.expected ? <p className="muted" data-testid="forecast-unavailable">{forecast.message}</p> : <ErrorNotice error={`Forecast: ${forecast.message}`} />)}
      <Section title="Report parameters">
        <form className="action-form" action="/ce" data-testid="cost-query">
          <div className="form-row">
            <Field label="Start">
              <input name="start" type="date" defaultValue={q.start} required />
            </Field>
            <Field label="End">
              <input name="end" type="date" defaultValue={q.end} required />
            </Field>
            <Field label="Granularity">
              <select name="granularity" defaultValue={q.granularity}>
                <option value="MONTHLY">Monthly</option>
                <option value="DAILY">Daily</option>
                <option value="HOURLY">Hourly</option>
              </select>
            </Field>
            <Field label="Metric">
              <select name="metric" defaultValue={q.metric}>
                {Object.entries(METRICS).map(([k, l]) => (
                  <option key={k} value={k}>
                    {l}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <div className="form-row">
            {groupSelect(0)}
            {groupSelect(1)}
          </div>
          <div className="form-row">
            <Field label="Filter">
              <select name="filter" defaultValue={q.filter ?? ""}>
                <option value="">None</option>
                {keyOptions.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Values" known={values} hint={values.length ? `e.g. ${values.slice(0, 3).join(", ")}` : "Comma separated"}>
              <input name="values" defaultValue={q.values.join(", ")} />
            </Field>
            <label className="check">
              <input type="checkbox" name="exclude" defaultChecked={q.exclude} /> Exclude
            </label>
          </div>
          <div className="form-actions">
            <button type="submit" className="button primary">
              Apply
              <span className="button-glyph">
                <Filter size={15} aria-hidden />
              </span>
            </button>
          </div>
        </form>
      </Section>
      <Section title={METRICS[q.metric]}>
        {periods.length === 0 ? (
          <Empty icon={ICONS.ce} />
        ) : (
          <div className="bars" role="img" aria-label="Costs by period">
            {periods.map((m) => (
              <div key={m.start} className="bar-col" title={`${m.label}: ${show(m.value)}${m.estimated ? " (estimated)" : ""}`}>
                <span className="bar-value">{m.value && periods.length <= 12 ? show(m.value) : ""}</span>
                <span className="bar" style={{ height: `${Math.max(2, (m.value / max) * 160)}px` }} />
                <span className="bar-label">{periods.length <= 31 ? m.label : ""}</span>
              </div>
            ))}
          </div>
        )}
      </Section>
      {q.groups.length > 0 && byLatest.length > 0 && (
        <Section title={`By ${q.groups.map(label).join(" / ").toLowerCase()}, ${periods.at(-1)?.label}`} count={byLatest.length}>
          <ul className="hbars" aria-label="Cost by group">
            {byLatest.map((s) => (
              <li key={s.name} title={`${s.name}: ${show(s.value)}`}>
                <AwsIcon icon={q.groups[0] === "DIMENSION:SERVICE" ? serviceIcon(s.name) : ICONS.ce} size={20} />
                <span className="hbar-name">{s.name || "No value"}</span>
                <span className="hbar-track">
                  <span className="hbar" style={{ width: `${(s.value / top) * 100}%` }} />
                </span>
                <span className="hbar-value">{show(s.value)}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}
      <Section title="Breakdown" count={q.groups.length ? groups.length : undefined} plain>
        <Table
          label="Cost breakdown"
          rowKey={(g) => g.key}
          rows={q.groups.length ? groups : [{ key: "Total", values: periods.map((p) => p.value), total: periods.reduce((n, p) => n + p.value, 0) }]}
          columns={[
            { header: q.groups.length ? q.groups.map(label).join(" / ") : "", cell: (g) => g.key || <span className="muted">No value</span> },
            ...periods.map((p, i) => ({ header: p.label, className: "num", cell: (g: { values: number[] }) => (g.values[i] ? show(g.values[i]) : "") })),
            { header: "Total", className: "num", cell: (g) => <b>{show(g.total)}</b> },
          ]}
          empty={<Empty icon={ICONS.ce} />}
        />
      </Section>
    </Page>
  );
}
