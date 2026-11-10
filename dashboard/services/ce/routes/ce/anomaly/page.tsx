import { GetAnomaliesCommand, GetAnomalyMonitorsCommand } from "@aws-sdk/client-cost-explorer";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Facts, List, Metric, Metrics, Page, Pill, Section } from "@mws-dashboard/ui";
import { CalendarCheck, ThumbsDown, ThumbsUp } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ce } from "../../../lib/clients";
import { addDays, day, money, mwsNow } from "../../../lib/clock";
import { href } from "../../../lib/query";
import { anomalyFeedback } from "../actions";

export const metadata: Metadata = { title: "Anomaly" };

type Props = { searchParams: Promise<{ id?: string; monitor?: string; start?: string }> };

const FEEDBACK: Record<string, string> = { YES: "Accurate anomaly", NO: "False positive", PLANNED_ACTIVITY: "Planned activity" };

export default async function Anomaly({ searchParams }: Props) {
  const { id = "", monitor, start } = await searchParams;
  const back = { href: "/ce/anomalies", label: "Cost anomaly detection" };
  const now = await mwsNow();
  const from = start ? new Date(`${start}T00:00:00Z`) : addDays(now, -90);
  const data = await load(async () => {
    const client = await ce();
    const [anomalies, monitors] = await Promise.all([
      all(
        (NextPageToken) => client.send(new GetAnomaliesCommand({ MonitorArn: monitor || undefined, DateInterval: { StartDate: day(addDays(from, -1)), EndDate: day(addDays(now, 1)) }, NextPageToken })),
        (r) => r.Anomalies,
        (r) => r.NextPageToken,
      ),
      all((NextPageToken) => client.send(new GetAnomalyMonitorsCommand({ NextPageToken, MonitorArnList: monitor ? [monitor] : undefined })), (r) => r.AnomalyMonitors, (r) => r.NextPageToken),
    ]);
    const a = anomalies.find((x) => x.AnomalyId === id);
    if (!a) throw new Error(`Anomaly ${id} was not found.`);
    return { a, monitor: monitors.find((m) => m.MonitorArn === a.MonitorArn) };
  });
  if (!data.ok) {
    return (
      <Page title="Anomaly" icon={ICONS.monitor} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { a, monitor: m } = data.value;
  const i = a.Impact;
  const startDay = a.AnomalyStartDate?.slice(0, 10);
  const endDay = a.AnomalyEndDate?.slice(0, 10);
  const range = startDay ? { start: day(addDays(new Date(`${startDay}T00:00:00Z`), -7)), end: day(addDays(new Date(`${endDay ?? startDay}T00:00:00Z`), 2)) } : {};
  const title = a.RootCauses?.[0]?.Service ?? a.DimensionValue ?? a.AnomalyId!;
  return (
    <Page
      title={title}
      icon={ICONS.monitor}
      back={back}
      subtitle={a.AnomalyId}
      actions={
        <>
          {(["YES", "NO", "PLANNED_ACTIVITY"] as const).map((f) => (
            <ActionForm
              key={f}
              action={anomalyFeedback.bind(null, a.AnomalyId!, f)}
              submit={FEEDBACK[f]}
              icon={f === "YES" ? <ThumbsUp size={15} /> : f === "NO" ? <ThumbsDown size={15} /> : <CalendarCheck size={15} />}
              tone={a.Feedback === f ? "primary" : "plain"}
            />
          ))}
        </>
      }
    >
      <Metrics>
        <Metric label="Total impact" value={money(i?.TotalImpact ?? 0)} tone="bad" />
        {i?.TotalImpactPercentage != null && <Metric label="Impact" value={`${i.TotalImpactPercentage.toFixed(1)}%`} />}
        {i?.TotalActualSpend != null && <Metric label="Actual spend" value={money(i.TotalActualSpend)} />}
        {i?.TotalExpectedSpend != null && <Metric label="Expected spend" value={money(i.TotalExpectedSpend)} />}
        <Metric label="Max daily impact" value={money(i?.MaxImpact ?? 0)} />
      </Metrics>
      <Section>
        <Facts
          items={[
            ["Monitor", m?.MonitorName ?? a.MonitorArn],
            ["Period", `${startDay ?? ""}${endDay && endDay !== startDay ? ` → ${endDay}` : ""}`],
            a.AnomalyScore && ["Score", `${a.AnomalyScore.CurrentScore?.toFixed(2)} (max ${a.AnomalyScore.MaxScore?.toFixed(2)})`],
            a.Feedback && ["Feedback", FEEDBACK[a.Feedback] ?? a.Feedback],
          ]}
        />
      </Section>
      <Section title="Root causes" count={a.RootCauses?.length ?? 0} plain>
        <List
          label="Root causes"
          rows={(a.RootCauses ?? []).map((r, n) => ({
            key: String(n),
            icon: <AwsIcon icon={ICONS.ce} size={22} />,
            title: r.Service ? <Link href={href({ ...range, granularity: "DAILY", groups: ["DIMENSION:USAGE_TYPE"], filter: "DIMENSION:SERVICE", values: [r.Service] })}>{r.Service}</Link> : "Unknown service",
            subtitle: [r.UsageType, r.Region, r.LinkedAccountName ?? r.LinkedAccount].filter(Boolean).join(" · "),
            meta: r.Impact?.Contribution != null ? <Pill tone="bad">+{money(r.Impact.Contribution)}</Pill> : undefined,
          }))}
        />
      </Section>
    </Page>
  );
}
