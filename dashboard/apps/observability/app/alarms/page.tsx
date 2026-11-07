import { DescribeAlarmsCommand } from "@aws-sdk/client-cloudwatch";
import { collect, load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, PageHeader, Section, Table, type Tone } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { cloudwatch } from "../../lib/clients";
import { setState } from "./actions";

export const metadata: Metadata = { title: "Alarms" };

const TONE: Record<string, Tone> = { OK: "good", ALARM: "bad", INSUFFICIENT_DATA: "neutral" };

function StateForm({ name }: { name: string }) {
  return (
    <ActionForm action={setState.bind(null, name)} submit="Set state" inline>
      <select name="state" aria-label="State" defaultValue="ALARM">
        <option>ALARM</option>
        <option>OK</option>
        <option>INSUFFICIENT_DATA</option>
      </select>
    </ActionForm>
  );
}

export default async function Alarms() {
  const alarms = await load(async () => {
    const client = await cloudwatch();
    const pages = await collect(
      (NextToken) => client.send(new DescribeAlarmsCommand({ NextToken, AlarmTypes: ["MetricAlarm", "CompositeAlarm"] })),
      (r) => [{ metric: r.MetricAlarms ?? [], composite: r.CompositeAlarms ?? [] }],
      (r) => r.NextToken,
    );
    return { metric: pages.flatMap((p) => p.metric), composite: pages.flatMap((p) => p.composite) };
  });
  if (!alarms.ok) {
    return (
      <>
        <PageHeader title="Alarms" />
        <ErrorNotice error={alarms.error} />
      </>
    );
  }
  return (
    <>
      <PageHeader title="Alarms" description="CloudWatch alarms in the selected region. They evaluate on MWS's emulated clock." />
      <Section title={`Metric alarms (${alarms.value.metric.length})`}>
        <Table
          label="Metric alarms"
          rows={alarms.value.metric}
          rowKey={(a) => a.AlarmArn!}
          empty="No metric alarms."
          columns={[
            { header: "Name", cell: (a) => <strong>{a.AlarmName}</strong> },
            { header: "State", cell: (a) => <Badge tone={TONE[a.StateValue ?? ""] ?? "neutral"}>{a.StateValue}</Badge> },
            {
              header: "Condition",
              className: "wrap",
              cell: (a) =>
                a.MetricName ? (
                  <code>
                    {a.Namespace} {a.MetricName} {a.Statistic ?? a.ExtendedStatistic} {a.ComparisonOperator} {a.Threshold} for{" "}
                    {a.EvaluationPeriods}×{a.Period}s
                  </code>
                ) : (
                  <span className="muted">metric math</span>
                ),
            },
            { header: "Actions", className: "wrap", cell: (a) => (a.AlarmActions ?? []).map((x) => <div key={x}><code>{x}</code></div>) },
            { header: "Updated", cell: (a) => when(a.StateUpdatedTimestamp) },
            { header: "", cell: (a) => <StateForm name={a.AlarmName!} /> },
          ]}
        />
      </Section>
      <Section title={`Composite alarms (${alarms.value.composite.length})`}>
        <Table
          label="Composite alarms"
          rows={alarms.value.composite}
          rowKey={(a) => a.AlarmArn!}
          empty="No composite alarms."
          columns={[
            { header: "Name", cell: (a) => <strong>{a.AlarmName}</strong> },
            { header: "State", cell: (a) => <Badge tone={TONE[a.StateValue ?? ""] ?? "neutral"}>{a.StateValue}</Badge> },
            { header: "Rule", className: "wrap", cell: (a) => <code>{a.AlarmRule}</code> },
            { header: "Updated", cell: (a) => when(a.StateUpdatedTimestamp) },
          ]}
        />
      </Section>
    </>
  );
}
