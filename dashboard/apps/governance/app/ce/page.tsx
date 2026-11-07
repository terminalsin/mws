import { GetCostAndUsageCommand, GetCostForecastCommand } from "@aws-sdk/client-cost-explorer";
import { load } from "@mws-dashboard/aws";
import { AwsIcon, Empty, ErrorNotice, Metric, Metrics, Page, Section, SERVICES } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, ce } from "../../lib/clients";

export const metadata: Metadata = { title: "Cost Explorer" };

const day = (d: Date) => d.toISOString().slice(0, 10);
const money = (n: number) => n.toLocaleString("en-US", { style: "currency", currency: "USD", minimumFractionDigits: n > 0 && n < 0.01 ? 4 : 2, maximumFractionDigits: n > 0 && n < 0.01 ? 4 : n < 10 ? 2 : 0 });

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

export default async function CostExplorer() {
  const now = new Date();
  const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const sixAgo = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 5, 1));
  const tomorrow = new Date(now.getTime() + 86_400_000);
  const nextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
  const data = await load(async () => {
    const client = await ce();
    const [months, services, forecast] = await Promise.all([
      client.send(new GetCostAndUsageCommand({ TimePeriod: { Start: day(sixAgo), End: day(tomorrow) }, Granularity: "MONTHLY", Metrics: ["UnblendedCost"] })),
      client.send(new GetCostAndUsageCommand({ TimePeriod: { Start: day(monthStart), End: day(tomorrow) }, Granularity: "MONTHLY", Metrics: ["UnblendedCost"], GroupBy: [{ Type: "DIMENSION", Key: "SERVICE" }] })),
      client.send(new GetCostForecastCommand({ TimePeriod: { Start: day(tomorrow), End: day(nextMonth) }, Granularity: "MONTHLY", Metric: "UNBLENDED_COST" })).catch(() => undefined),
    ]);
    return { months, services, forecast };
  });
  if (!data.ok) {
    return (
      <Page title="Cost and usage">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const monthly = (data.value.months.ResultsByTime ?? []).map((r) => ({ label: new Date(r.TimePeriod!.Start! + "T00:00:00Z").toLocaleString("en-US", { month: "short", timeZone: "UTC" }), value: Number(r.Total?.UnblendedCost?.Amount ?? 0) }));
  const byService = (data.value.services.ResultsByTime?.[0]?.Groups ?? [])
    .map((g) => ({ name: g.Keys![0], value: Number(g.Metrics?.UnblendedCost?.Amount ?? 0) }))
    .filter((g) => g.value > 0)
    .sort((a, b) => b.value - a.value);
  const mtd = monthly.at(-1)?.value ?? 0;
  const last = monthly.at(-2)?.value ?? 0;
  const forecast = mtd + Number(data.value.forecast?.Total?.Amount ?? 0);
  const max = Math.max(...monthly.map((m) => m.value), 0.01);
  const top = byService[0]?.value ?? 1;
  return (
    <Page title="Cost and usage">
      <Metrics>
        <Metric label="Month to date" value={money(mtd)} />
        {data.value.forecast && <Metric label="Forecast this month" value={money(forecast)} tone={last && forecast > last * 1.2 ? "warn" : undefined} />}
        <Metric label="Last month" value={money(last)} />
      </Metrics>
      <Section title="Monthly costs">
        <div className="bars" role="img" aria-label="Monthly costs">
          {monthly.map((m) => (
            <div key={m.label} className="bar-col" title={`${m.label}: ${money(m.value)}`}>
              <span className="bar-value">{m.value ? money(m.value) : ""}</span>
              <span className="bar" style={{ height: `${Math.max(2, (m.value / max) * 160)}px` }} />
              <span className="bar-label">{m.label}</span>
            </div>
          ))}
        </div>
      </Section>
      <Section title="By service this month" count={byService.length}>
        {byService.length === 0 ? (
          <Empty icon={ICONS.ce} />
        ) : (
          <ul className="hbars" aria-label="Cost by service">
            {byService.map((s) => (
              <li key={s.name} title={`${s.name}: ${money(s.value)}`}>
                <AwsIcon icon={serviceIcon(s.name)} size={20} />
                <span className="hbar-name">{s.name}</span>
                <span className="hbar-track">
                  <span className="hbar" style={{ width: `${(s.value / top) * 100}%` }} />
                </span>
                <span className="hbar-value">{money(s.value)}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </Page>
  );
}
