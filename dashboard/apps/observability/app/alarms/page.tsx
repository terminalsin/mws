import { ListMetricsCommand, type MetricAlarm } from "@aws-sdk/client-cloudwatch";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Metric, Metrics, Page, Sheet, Status } from "@mws-dashboard/ui";
import { BellOff, BellRing, CircleCheck, Siren, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ALARM_TONE, ICONS, cloudwatch, listAlarms, metricHref, sourceIcon } from "../../lib/clients";
import { createAlarm, deleteAlarm, setActions, setState } from "./actions";

export const metadata: Metadata = { title: "Alarms" };

const OP: Record<string, string> = {
  GreaterThanThreshold: ">",
  GreaterThanOrEqualToThreshold: "≥",
  LessThanThreshold: "<",
  LessThanOrEqualToThreshold: "≤",
  LessThanLowerOrGreaterThanUpperThreshold: "outside",
  LessThanLowerThreshold: "<",
  GreaterThanUpperThreshold: ">",
};

const period = (s: number | undefined) => (!s ? "" : s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`);

/** "Sum(Orders) > 100 for 2 × 1 min": the alarm's rule as one line. */
function rule(a: MetricAlarm) {
  if (!a.MetricName) return a.ThresholdMetricId ? `anomaly band ${a.ThresholdMetricId}` : `${a.Metrics?.length ?? 0} metric math`;
  const times = (a.EvaluationPeriods ?? 1) > 1 ? `${a.DatapointsToAlarm ?? a.EvaluationPeriods}/${a.EvaluationPeriods} × ` : "";
  return `${a.Statistic ?? a.ExtendedStatistic}(${a.MetricName}) ${OP[a.ComparisonOperator ?? ""] ?? a.ComparisonOperator} ${a.Threshold} · ${times}${period(a.Period)}`;
}

const STATES = [
  { id: "ALARM", title: "In alarm" },
  { id: "INSUFFICIENT_DATA", title: "Insufficient data" },
  { id: "OK", title: "OK" },
];

export default async function Alarms() {
  const [alarms, metrics] = await Promise.all([
    load(listAlarms),
    load(async () => {
      const c = await cloudwatch();
      return collect((NextToken) => c.send(new ListMetricsCommand({ NextToken })), (r) => r.Metrics, (r) => r.NextToken, 2000);
    }),
  ]);
  const namespaces = metrics.ok ? [...new Set(metrics.value.map((m) => m.Namespace!))].sort() : [];
  const names = metrics.ok ? [...new Set(metrics.value.map((m) => m.MetricName!))].sort() : [];
  const create = (
    <Sheet title="New alarm" label="Create alarm" testId="create-alarm">
      <ActionForm action={createAlarm} submit="Create" testId="create-alarm">
        <Field label="Name">
          <input name="name" required autoFocus />
        </Field>
        <Field label="Namespace">
          <input name="namespace" required list="namespaces" />
        </Field>
        <datalist id="namespaces">{namespaces.map((n) => <option key={n} value={n} />)}</datalist>
        <Field label="Metric">
          <input name="metric" required list="metric-names" />
        </Field>
        <datalist id="metric-names">{names.map((n) => <option key={n} value={n} />)}</datalist>
        <Field label="Dimensions">
          <input name="dims" placeholder="QueueName=orders" />
        </Field>
        <div className="form-grid">
          <Field label="Statistic">
            <select name="stat" defaultValue="Sum">
              {["Sum", "Average", "Maximum", "Minimum", "SampleCount"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
          <Field label="Condition">
            <select name="comparison" defaultValue="GreaterThanThreshold">
              {Object.entries(OP)
                .slice(0, 4)
                .map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
            </select>
          </Field>
          <Field label="Threshold">
            <input name="threshold" type="number" step="any" required />
          </Field>
          <Field label="Period (s)">
            <input name="period" type="number" defaultValue={60} min={10} />
          </Field>
          <Field label="Periods">
            <input name="evaluations" type="number" defaultValue={1} min={1} />
          </Field>
          <Field label="Missing data">
            <select name="missing" defaultValue="missing">
              {["missing", "notBreaching", "breaching", "ignore"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
        </div>
        <Field label="Notify (SNS topic ARN)">
          <input name="action" placeholder="arn:aws:sns:…" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!alarms.ok) {
    return (
      <Page title="Alarms" actions={create}>
        <ErrorNotice error={alarms.error} />
      </Page>
    );
  }
  const all = [...alarms.value.metric, ...alarms.value.composite.map((c) => ({ ...c, composite: true as const }))];
  const count = (s: string) => all.filter((a) => a.StateValue === s).length;
  return (
    <Page title="Alarms" actions={create}>
      {all.length > 0 && (
        <Metrics>
          <Metric label="In alarm" value={count("ALARM")} tone={count("ALARM") ? "bad" : undefined} icon={<Siren size={14} />} />
          <Metric label="Insufficient" value={count("INSUFFICIENT_DATA")} />
          <Metric label="OK" value={count("OK")} tone="good" icon={<CircleCheck size={14} />} />
        </Metrics>
      )}
      <Curated
        label="Alarms"
        sections={STATES.map((s) => ({ ...s, items: all.filter((a) => a.StateValue === s.id) }))}
        empty={<Empty icon={ICONS.alarm} />}
        row={(a) => {
          const metric = "MetricName" in a && a.MetricName ? (a as MetricAlarm) : null;
          const icon = metric?.Namespace ? sourceIcon(metric.Namespace) : undefined;
          const name = a.AlarmName!;
          return {
            key: a.AlarmArn!,
            icon: <AwsIcon icon={icon ?? ICONS.alarm} size={22} />,
            title: name,
            subtitle: "composite" in a ? a.AlarmRule : rule(a as MetricAlarm),
            href: metric ? metricHref(metric.Namespace!, metric.MetricName!, metric.Dimensions) : undefined,
            meta: (
              <>
                {!a.ActionsEnabled && <BellOff size={14} aria-label="Actions muted" />}
                <Status tone={ALARM_TONE[a.StateValue ?? ""] ?? "neutral"}>{ago(a.StateUpdatedTimestamp)}</Status>
              </>
            ),
            actions: (
              <>
                {a.StateValue !== "ALARM" ? (
                  <ActionForm action={setState.bind(null, name, "ALARM")} submit={`Set ${name} to ALARM`} icon={<Siren size={15} />} />
                ) : (
                  <ActionForm action={setState.bind(null, name, "OK")} submit={`Set ${name} to OK`} icon={<CircleCheck size={15} />} />
                )}
                <ActionForm
                  action={setActions.bind(null, name, !a.ActionsEnabled)}
                  submit={a.ActionsEnabled ? `Mute ${name}` : `Unmute ${name}`}
                  icon={a.ActionsEnabled ? <BellOff size={15} /> : <BellRing size={15} />}
                />
                <ActionForm action={deleteAlarm.bind(null, name)} submit={`Delete ${name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${name}?`} />
              </>
            ),
          };
        }}
      />
    </Page>
  );
}
