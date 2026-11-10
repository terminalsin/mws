import {
  GetAnomaliesCommand,
  GetAnomalyMonitorsCommand,
  GetAnomalySubscriptionsCommand,
  GetDimensionValuesCommand,
  GetTagsCommand,
  type AnomalyMonitor,
  type AnomalySubscription,
} from "@aws-sdk/client-cost-explorer";
import { ListTopicsCommand } from "@aws-sdk/client-sns";
import { frameInfo, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Section } from "@mws-dashboard/ui";
import { Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ce, sns } from "../../../lib/clients";
import { deleteMonitor, deleteSubscription } from "../actions";
import { NewMonitor, NewSubscription } from "./forms";

export const metadata: Metadata = { title: "Cost anomaly detection" };

const day = (d: Date) => d.toISOString().slice(0, 10);
const usd = (n: number) => n.toLocaleString("en-US", { style: "currency", currency: "USD", maximumFractionDigits: n < 10 ? 2 : 0 });

function watches(m: AnomalyMonitor) {
  if (m.MonitorType === "DIMENSIONAL") return m.MonitorDimension === "SERVICE" ? "AWS services" : "Linked accounts";
  const spec = m.MonitorSpecification;
  if (spec?.Tags) return `${spec.Tags.Key} = ${(spec.Tags.Values ?? []).join(", ")}`;
  if (spec?.Dimensions) return (spec.Dimensions.Values ?? []).join(", ");
  if (spec?.CostCategories) return `${spec.CostCategories.Key} = ${(spec.CostCategories.Values ?? []).join(", ")}`;
  return "Custom";
}

function threshold(s: AnomalySubscription) {
  const d = s.ThresholdExpression?.Dimensions;
  if (d?.Values?.[0]) return d.Key === "ANOMALY_TOTAL_IMPACT_PERCENTAGE" ? `≥ ${d.Values[0]}%` : `≥ ${usd(Number(d.Values[0]))}`;
  return s.Threshold !== undefined ? `≥ ${usd(s.Threshold)}` : undefined;
}

export default async function Anomalies() {
  const now = new Date();
  const period = { Start: day(new Date(now.getTime() - 90 * 86_400_000)), End: day(new Date(now.getTime() + 86_400_000)) };
  const data = await load(async () => {
    const client = await ce();
    const [monitors, subscriptions, anomalies, accounts, tags, topics, info] = await Promise.all([
      client.send(new GetAnomalyMonitorsCommand({})),
      client.send(new GetAnomalySubscriptionsCommand({})),
      client.send(new GetAnomaliesCommand({ DateInterval: { StartDate: period.Start, EndDate: period.End } })),
      // Suggestions only: the forms work without them.
      client.send(new GetDimensionValuesCommand({ TimePeriod: period, Dimension: "LINKED_ACCOUNT" })).catch(() => undefined),
      client.send(new GetTagsCommand({ TimePeriod: period })).catch(() => undefined),
      (async () => (await sns()).send(new ListTopicsCommand({})))().catch(() => undefined),
      frameInfo(),
    ]);
    return { monitors, subscriptions, anomalies, accounts, tags, topics, info };
  });
  if (!data.ok) {
    return (
      <Page title="Cost anomaly detection">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const monitors = data.value.monitors.AnomalyMonitors ?? [];
  const subscriptions = data.value.subscriptions.AnomalySubscriptions ?? [];
  const anomalies = (data.value.anomalies.Anomalies ?? []).sort((a, b) => (b.Impact?.TotalImpact ?? 0) - (a.Impact?.TotalImpact ?? 0));
  const names = Object.fromEntries(monitors.map((m) => [m.MonitorArn!, m.MonitorName!]));
  const { account, region } = data.value.info;
  const monitorForm = (
    <NewMonitor
      names={monitors.map((m) => m.MonitorName!)}
      hasServices={monitors.some((m) => m.MonitorType === "DIMENSIONAL" && m.MonitorDimension === "SERVICE")}
      accounts={[...new Set([...(data.value.accounts?.DimensionValues ?? []).map((v) => v.Value!), ...(account ? [account] : [])])]}
      tagKeys={data.value.tags?.Tags ?? []}
    />
  );
  return (
    <Page title="Cost anomaly detection" actions={monitorForm}>
      {anomalies.length > 0 && (
        <Section title="Detected anomalies" count={anomalies.length} plain>
          <List
            label="Anomalies"
            rows={anomalies.map((a) => ({
              key: a.AnomalyId!,
              icon: <AwsIcon icon={ICONS.monitor} size={24} />,
              title: a.RootCauses?.[0]?.Service ?? names[a.MonitorArn!] ?? a.AnomalyId!,
              subtitle: [a.AnomalyStartDate?.slice(0, 10), names[a.MonitorArn!]].filter(Boolean).join(" · "),
              meta: <Pill tone="bad">+{usd(a.Impact?.TotalImpact ?? 0)}</Pill>,
            }))}
          />
        </Section>
      )}
      <Section title="Monitors" count={monitors.length} plain>
        <List
          label="Monitors"
          empty={<Empty icon={ICONS.monitor} action={monitorForm} />}
          rows={monitors.map((m) => ({
            key: m.MonitorArn!,
            icon: <AwsIcon icon={ICONS.monitor} size={24} />,
            title: m.MonitorName!,
            subtitle: watches(m),
            meta: m.LastEvaluatedDate ? <span>{m.LastEvaluatedDate.slice(0, 10)}</span> : undefined,
            actions: (
              <ActionForm action={deleteMonitor.bind(null, m.MonitorArn!)} submit={`Delete ${m.MonitorName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${m.MonitorName}?`} />
            ),
          }))}
        />
      </Section>
      {monitors.length > 0 && (
        <Section
          title="Alert subscriptions"
          count={subscriptions.length}
          plain
          actions={
            <NewSubscription
              names={subscriptions.map((s) => s.SubscriptionName!)}
              monitors={monitors.map((m) => ({ arn: m.MonitorArn!, name: m.MonitorName! }))}
              topics={(data.value.topics?.Topics ?? []).map((t) => t.TopicArn!)}
              topicArn={account ? `arn:aws:sns:${region}:${account}:{}` : undefined}
            />
          }
        >
          <List
            label="Alert subscriptions"
            empty={<Empty icon={ICONS.subscription} />}
            rows={subscriptions.map((s) => {
              const to = s.Subscribers?.[0];
              return {
                key: s.SubscriptionArn!,
                icon: <AwsIcon icon={to?.Type === "SNS" ? ICONS.topic : ICONS.email} size={24} />,
                title: s.SubscriptionName!,
                subtitle: [to?.Address, ...(s.MonitorArnList ?? []).map((a) => names[a] ?? a)].filter(Boolean).join(" · "),
                meta: (
                  <>
                    {threshold(s) && <Pill>{threshold(s)}</Pill>}
                    <Pill tone="info">{s.Frequency === "IMMEDIATE" ? "Immediate" : s.Frequency === "DAILY" ? "Daily" : "Weekly"}</Pill>
                  </>
                ),
                actions: (
                  <ActionForm
                    action={deleteSubscription.bind(null, s.SubscriptionArn!)}
                    submit={`Delete ${s.SubscriptionName}`}
                    icon={<Trash2 size={15} />}
                    tone="danger"
                    confirm={`Delete ${s.SubscriptionName}?`}
                  />
                ),
              };
            })}
          />
        </Section>
      )}
    </Page>
  );
}
