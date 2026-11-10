"use client";

// The metric alarm form's fields. A new alarm opens on the common alarms
// (EC2 CPU, Lambda errors, queue backlog...): picking one fills the metric,
// statistic, period and a sensible threshold, so only the resource (its
// dimension), the threshold and who to tell stay in view. Custom shows
// every field. Namespaces with metrics here get a green dot.

import type { MetricAlarm } from "@aws-sdk/client-cloudwatch";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { PutMetricAlarm as Rules } from "@mws-dashboard/ui/model/cloudwatch";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { Wrench } from "lucide-react";
import { useState } from "react";

import { OP, PERIODS, STATISTICS, period } from "./alarm-consts";
import { ALARM_PRESETS, type AlarmPreset } from "./alarm-presets";

const NAMESPACE: Rule = { ...Rules.Namespace, required: true, hint: "Can't start with :" };
const METRIC: Rule = { ...Rules.MetricName, required: true };
const DIMENSIONS: Rule = { format: "pairs", maxLength: 4096 };
const TAGS: Rule = { format: "tags", maxLength: 8192 };
/** A list of action ARNs: each checked as an ARN, bare topic names expand
 * to the topic's ARN and close names suggest known topics. */
const actionsRule = (r: Rule, known: string[], arn?: string): Rule => ({
  ...r,
  item: { ...r.item!, format: "arn", known, ...(arn ? { arn } : {}) },
});

const CUSTOM = { id: "custom", label: "Custom", icon: <Wrench size={22} aria-hidden /> };

const lines = (dims: { Name?: string; Value?: string }[] | undefined) => (dims ?? []).map((d) => `${d.Name}=${d.Value}`).join("\n");

/** Actions for each state: SNS topics, Lambda functions, Auto Scaling
 * policies or EC2 actions, one ARN per line. */
export function ActionFields({
  alarm,
  topics,
  topicArn,
  fold,
}: {
  alarm?: { AlarmActions?: string[]; OKActions?: string[]; InsufficientDataActions?: string[] };
  topics: string[];
  topicArn?: string;
  /** Fold the OK and insufficient-data actions under More. */
  fold?: boolean;
}) {
  const rest = (
    <>
      <FieldShell label="OK" rule={actionsRule(Rules.OKActions, topics, topicArn)}>
        <textarea name="ok" rows={1} defaultValue={alarm?.OKActions?.join("\n")} />
      </FieldShell>
      <FieldShell label="Insufficient data" rule={actionsRule(Rules.InsufficientDataActions, topics, topicArn)}>
        <textarea name="insufficient" rows={1} defaultValue={alarm?.InsufficientDataActions?.join("\n")} />
      </FieldShell>
    </>
  );
  return (
    <>
      <FieldShell label="In alarm" rule={actionsRule(Rules.AlarmActions, topics, topicArn)} hint="SNS topic, Lambda function or Auto Scaling policy ARNs">
        <textarea name="action" rows={2} placeholder={topics[0] ?? "arn:aws:sns:…"} defaultValue={alarm?.AlarmActions?.join("\n")} />
      </FieldShell>
      {fold ? null : rest}
    </>
  );
}

function OtherActions({ topics, topicArn }: { topics: string[]; topicArn?: string }) {
  return (
    <>
      <FieldShell label="OK" rule={actionsRule(Rules.OKActions, topics, topicArn)}>
        <textarea name="ok" rows={1} />
      </FieldShell>
      <FieldShell label="Insufficient data" rule={actionsRule(Rules.InsufficientDataActions, topics, topicArn)}>
        <textarea name="insufficient" rows={1} />
      </FieldShell>
    </>
  );
}

export function AlarmFields({
  alarm,
  namespaces,
  names,
  dims,
  taken,
  topics,
  topicArn,
  dimsByNamespace = {},
  testId,
}: {
  alarm?: MetricAlarm;
  namespaces: string[];
  names: string[];
  dims: string[];
  taken: string[];
  topics: string[];
  topicArn?: string;
  dimsByNamespace?: Record<string, string[]>;
  testId: string;
}) {
  const [chosen, setChosen] = useState<AlarmPreset | null>(null);
  const edit = !!alarm;
  const p = edit ? null : chosen;
  const math = !!alarm?.Metrics?.length;
  const stat = alarm?.Statistic ?? alarm?.ExtendedStatistic ?? p?.stat ?? "Sum";
  const statistics = STATISTICS.includes(stat) ? STATISTICS : [...STATISTICS, stat];
  const ops = alarm?.ThresholdMetricId ? Object.keys(OP).slice(4) : Object.keys(OP).slice(0, 4);
  const per = alarm?.Period ?? p?.period ?? 60;
  // A preset's resource: the first one of this namespace that has the dimension.
  const known = p ? (dimsByNamespace[p.namespace] ?? []) : dims;
  const dimDefault = p
    ? p.dimensionValue
      ? `${p.dimension}=${p.dimensionValue}`
      : (known.find((d) => d.startsWith(`${p.dimension}=`) && !d.includes(","))?.replace(/, /g, "\n") ?? "")
    : lines(alarm?.Dimensions);

  const metricFields = (
    <>
      <FieldShell label="Namespace" rule={NAMESPACE} known={namespaces}>
        <input name="namespace" list={`${testId}-namespaces`} defaultValue={alarm?.Namespace ?? p?.namespace} />
      </FieldShell>
      <datalist id={`${testId}-namespaces`}>
        {namespaces.map((n) => (
          <option key={n} value={n} />
        ))}
      </datalist>
      <FieldShell label="Metric" rule={METRIC} known={names}>
        <input name="metric" list={`${testId}-metric-names`} defaultValue={alarm?.MetricName ?? p?.metric} />
      </FieldShell>
      <datalist id={`${testId}-metric-names`}>
        {names.map((n) => (
          <option key={n} value={n} />
        ))}
      </datalist>
    </>
  );
  const statField = (
    <FieldShell label="Statistic" rule={{ type: "string" }}>
      <select name="stat" defaultValue={stat}>
        {statistics.map((s) => (
          <option key={s}>{s}</option>
        ))}
      </select>
    </FieldShell>
  );
  const periodField = (
    <FieldShell label="Period" rule={Rules.Period}>
      <select name="period" defaultValue={per}>
        {(PERIODS.some(([s]) => s === per) ? PERIODS : [...PERIODS, [per, period(per)] as [number, string]]).map(([s, label]) => (
          <option key={s} value={s}>
            {label}
          </option>
        ))}
      </select>
    </FieldShell>
  );
  const evaluationsField = (
    <FieldShell label="Periods" rule={Rules.EvaluationPeriods}>
      <input name="evaluations" type="number" defaultValue={alarm?.EvaluationPeriods ?? p?.evaluations ?? 1} />
    </FieldShell>
  );
  const rare = (
    <>
      <div className="form-grid">
        <FieldShell label="Datapoints to alarm" rule={Rules.DatapointsToAlarm}>
          <input name="datapoints" type="number" placeholder="all" defaultValue={alarm?.DatapointsToAlarm ?? p?.datapoints} />
        </FieldShell>
        <FieldShell label="Missing data" rule={Rules.TreatMissingData}>
          <select name="missing" defaultValue={alarm?.TreatMissingData ?? p?.missing ?? "missing"}>
            {["missing", "notBreaching", "breaching", "ignore"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </FieldShell>
      </div>
      <FieldShell label="Description" rule={Rules.AlarmDescription}>
        <input name="description" defaultValue={alarm?.AlarmDescription ?? p?.title} />
      </FieldShell>
    </>
  );

  return (
    <>
      {!edit && (
        <PresetGallery
          presets={[...ALARM_PRESETS.map((a) => ({ ...a, found: namespaces.includes(a.namespace) })), CUSTOM]}
          chosen={chosen?.id ?? CUSTOM.id}
          choose={(x) => setChosen(ALARM_PRESETS.find((a) => a.id === x.id) ?? null)}
          label="Alarm"
          size={26}
        />
      )}
      <div key={p?.id ?? "custom"} className="preset-fields">
        {edit ? (
          <input type="hidden" name="enabled" value={alarm.ActionsEnabled === false ? "off" : "on"} />
        ) : (
          <FieldShell label="Name" rule={Rules.AlarmName} taken={taken} generate="name" unique>
            <input name="name" autoFocus defaultValue={p ? freeName(p.base, taken) : undefined} />
          </FieldShell>
        )}
        {math ? (
          <>
            <FieldShell label="Metric math" rule={{ format: "json" }} hint="MetricDataQuery list">
              <textarea name="metrics" rows={6} className="code-editor" defaultValue={JSON.stringify(alarm!.Metrics, null, 2)} />
            </FieldShell>
            {alarm?.ThresholdMetricId && <input type="hidden" name="thresholdMetric" value={alarm.ThresholdMetricId} />}
          </>
        ) : (
          <>
            {!p && metricFields}
            <FieldShell label={p?.dimension && !p.dimensionValue ? p.dimension : "Dimensions"} rule={DIMENSIONS} known={known}>
              <textarea name="dims" rows={p ? 1 : 2} placeholder={p?.dimension ? `${p.dimension}=…` : "QueueName=orders"} defaultValue={dimDefault} />
            </FieldShell>
          </>
        )}
        <div className="form-grid">
          {!math && !p && statField}
          <FieldShell label="Condition" rule={Rules.ComparisonOperator}>
            <select name="comparison" defaultValue={alarm?.ComparisonOperator ?? p?.comparison ?? ops[0]}>
              {ops.map((k) => (
                <option key={k} value={k}>
                  {OP[k]}
                </option>
              ))}
            </select>
          </FieldShell>
          {!alarm?.ThresholdMetricId && (
            <FieldShell label="Threshold" rule={{ ...Rules.Threshold, required: true }}>
              <input name="threshold" type="number" step="any" defaultValue={alarm?.Threshold ?? p?.threshold} />
            </FieldShell>
          )}
          {!math && !p && periodField}
          {!p && evaluationsField}
        </div>
        <ActionFields alarm={alarm} topics={topics} topicArn={topicArn} fold={!edit} />
        <MoreFields open={edit}>
          {p && (
            <>
              {metricFields}
              <div className="form-grid">
                {statField}
                {periodField}
                {evaluationsField}
              </div>
            </>
          )}
          {rare}
          {!edit && <OtherActions topics={topics} topicArn={topicArn} />}
          {!edit && (
            <FieldShell label="Tags" rule={TAGS}>
              <textarea name="tags" rows={1} placeholder="team=payments" />
            </FieldShell>
          )}
        </MoreFields>
      </div>
    </>
  );
}
