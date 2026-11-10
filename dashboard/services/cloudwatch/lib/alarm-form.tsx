import type { CompositeAlarm, MetricAlarm } from "@aws-sdk/client-cloudwatch";
import { ActionForm, Field, type Rule } from "@mws-dashboard/ui";
import {
  PutCompositeAlarm,
  PutMetricAlarm as Rules,
} from "@mws-dashboard/ui/model/cloudwatch";

import { dimsText } from "./clients";

export const OP: Record<string, string> = {
  GreaterThanThreshold: ">",
  GreaterThanOrEqualToThreshold: "≥",
  LessThanThreshold: "<",
  LessThanOrEqualToThreshold: "≤",
  LessThanLowerOrGreaterThanUpperThreshold: "outside",
  LessThanLowerThreshold: "<",
  GreaterThanUpperThreshold: ">",
};

export const period = (s: number | undefined) =>
  !s
    ? ""
    : s % 86400 === 0
      ? `${s / 86400} d`
      : s % 3600 === 0
        ? `${s / 3600} h`
        : s % 60 === 0
          ? `${s / 60} min`
          : `${s} s`;

// Periods the AWS console offers; PutMetricAlarm takes 10, 20, 30 or any multiple of 60.
export const PERIODS: [number, string][] = [
  [10, "10 s"],
  [30, "30 s"],
  [60, "1 min"],
  [300, "5 min"],
  [900, "15 min"],
  [3600, "1 h"],
  [21600, "6 h"],
  [86400, "1 day"],
];

/** The statistics the console offers: the five standard ones, then the
 * common percentiles (sent as ExtendedStatistic). */
export const STATISTICS = [
  "Sum",
  "Average",
  "Maximum",
  "Minimum",
  "SampleCount",
  "p99",
  "p95",
  "p90",
  "p50",
];

const NAMESPACE: Rule = {
  ...Rules.Namespace,
  required: true,
  hint: "Can't start with :",
};
const METRIC: Rule = { ...Rules.MetricName, required: true };
const DIMENSIONS: Rule = { format: "pairs", maxLength: 4096 };
const TAGS: Rule = { format: "tags", maxLength: 8192 };
/** A list of action ARNs: each checked as an ARN, bare topic names expand
 * to the topic's ARN and close names suggest known topics. */
const actionsRule = (r: Rule, known: string[], arn?: string): Rule => ({
  ...r,
  item: { ...r.item!, format: "arn", known, ...(arn ? { arn } : {}) },
});

export interface AlarmFormProps {
  /** The alarm being edited; a new one when absent. */
  alarm?: MetricAlarm;
  namespaces: string[];
  names: string[];
  dims: string[];
  taken: string[];
  topics: string[];
  topicArn?: string;
  action: (
    previous: import("@mws-dashboard/ui").ActionResult | null,
    form: FormData,
  ) => Promise<import("@mws-dashboard/ui").ActionResult>;
  testId: string;
}

/** Actions for each state: SNS topics, Lambda functions, Auto Scaling
 * policies or EC2 actions, one ARN per line. */
function ActionFields({
  alarm,
  topics,
  topicArn,
}: {
  alarm?: {
    AlarmActions?: string[];
    OKActions?: string[];
    InsufficientDataActions?: string[];
  };
  topics: string[];
  topicArn?: string;
}) {
  return (
    <>
      <Field
        label="In alarm"
        rule={actionsRule(Rules.AlarmActions, topics, topicArn)}
        hint="SNS topic, Lambda function or Auto Scaling policy ARNs"
      >
        <textarea
          name="action"
          rows={2}
          placeholder="arn:aws:sns:…"
          defaultValue={alarm?.AlarmActions?.join("\n")}
        />
      </Field>
      <Field label="OK" rule={actionsRule(Rules.OKActions, topics, topicArn)}>
        <textarea
          name="ok"
          rows={1}
          defaultValue={alarm?.OKActions?.join("\n")}
        />
      </Field>
      <Field
        label="Insufficient data"
        rule={actionsRule(Rules.InsufficientDataActions, topics, topicArn)}
      >
        <textarea
          name="insufficient"
          rows={1}
          defaultValue={alarm?.InsufficientDataActions?.join("\n")}
        />
      </Field>
    </>
  );
}

export function AlarmForm({
  alarm,
  namespaces,
  names,
  dims,
  taken,
  topics,
  topicArn,
  action,
  testId,
}: AlarmFormProps) {
  const math = !!alarm?.Metrics?.length;
  const stat = alarm?.Statistic ?? alarm?.ExtendedStatistic ?? "Sum";
  const statistics = STATISTICS.includes(stat)
    ? STATISTICS
    : [...STATISTICS, stat];
  const ops = alarm?.ThresholdMetricId
    ? Object.keys(OP).slice(4)
    : Object.keys(OP).slice(0, 4);
  return (
    <ActionForm
      action={action}
      submit={alarm ? "Save" : "Create"}
      testId={testId}
    >
      {alarm ? (
        <input
          type="hidden"
          name="enabled"
          value={alarm.ActionsEnabled === false ? "off" : "on"}
        />
      ) : (
        <Field
          label="Name"
          rule={Rules.AlarmName}
          taken={taken}
          generate="name"
          unique
        >
          <input name="name" autoFocus />
        </Field>
      )}
      <Field label="Description" rule={Rules.AlarmDescription}>
        <input name="description" defaultValue={alarm?.AlarmDescription} />
      </Field>
      {math ? (
        <>
          <Field
            label="Metric math"
            rule={{ format: "json" }}
            hint="MetricDataQuery list"
          >
            <textarea
              name="metrics"
              rows={6}
              className="code-editor"
              defaultValue={JSON.stringify(alarm!.Metrics, null, 2)}
            />
          </Field>
          {alarm?.ThresholdMetricId && (
            <input
              type="hidden"
              name="thresholdMetric"
              value={alarm.ThresholdMetricId}
            />
          )}
        </>
      ) : (
        <>
          <Field label="Namespace" rule={NAMESPACE} known={namespaces}>
            <input
              name="namespace"
              list={`${testId}-namespaces`}
              defaultValue={alarm?.Namespace}
            />
          </Field>
          <datalist id={`${testId}-namespaces`}>
            {namespaces.map((n) => (
              <option key={n} value={n} />
            ))}
          </datalist>
          <Field label="Metric" rule={METRIC} known={names}>
            <input
              name="metric"
              list={`${testId}-metric-names`}
              defaultValue={alarm?.MetricName}
            />
          </Field>
          <datalist id={`${testId}-metric-names`}>
            {names.map((n) => (
              <option key={n} value={n} />
            ))}
          </datalist>
          <Field label="Dimensions" rule={DIMENSIONS} known={dims}>
            <textarea
              name="dims"
              rows={2}
              placeholder="QueueName=orders"
              defaultValue={dimsText(alarm?.Dimensions).replace(/, /g, "\n")}
            />
          </Field>
        </>
      )}
      <div className="form-grid">
        {!math && (
          <Field label="Statistic" rule={{ type: "string" }}>
            <select name="stat" defaultValue={stat}>
              {statistics.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Condition" rule={Rules.ComparisonOperator}>
          <select
            name="comparison"
            defaultValue={alarm?.ComparisonOperator ?? ops[0]}
          >
            {ops.map((k) => (
              <option key={k} value={k}>
                {OP[k]}
              </option>
            ))}
          </select>
        </Field>
        {!alarm?.ThresholdMetricId && (
          <Field
            label="Threshold"
            rule={{ ...Rules.Threshold, required: true }}
          >
            <input
              name="threshold"
              type="number"
              step="any"
              defaultValue={alarm?.Threshold}
            />
          </Field>
        )}
        {!math && (
          <Field label="Period" rule={Rules.Period}>
            <select name="period" defaultValue={alarm?.Period ?? 60}>
              {(PERIODS.some(([s]) => s === alarm?.Period) || !alarm?.Period
                ? PERIODS
                : [
                    ...PERIODS,
                    [alarm.Period, period(alarm.Period)] as [number, string],
                  ]
              ).map(([s, label]) => (
                <option key={s} value={s}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Periods" rule={Rules.EvaluationPeriods}>
          <input
            name="evaluations"
            type="number"
            defaultValue={alarm?.EvaluationPeriods ?? 1}
          />
        </Field>
        <Field label="Datapoints to alarm" rule={Rules.DatapointsToAlarm}>
          <input
            name="datapoints"
            type="number"
            placeholder="all"
            defaultValue={alarm?.DatapointsToAlarm}
          />
        </Field>
        <Field label="Missing data" rule={Rules.TreatMissingData}>
          <select
            name="missing"
            defaultValue={alarm?.TreatMissingData ?? "missing"}
          >
            {["missing", "notBreaching", "breaching", "ignore"].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </Field>
      </div>
      <ActionFields alarm={alarm} topics={topics} topicArn={topicArn} />
      {!alarm && (
        <Field label="Tags" rule={TAGS}>
          <textarea name="tags" rows={1} placeholder="team=payments" />
        </Field>
      )}
    </ActionForm>
  );
}

export function CompositeForm({
  alarm,
  taken,
  alarms,
  topics,
  topicArn,
  action,
  testId,
}: {
  alarm?: CompositeAlarm;
  taken: string[];
  alarms: string[];
  topics: string[];
  topicArn?: string;
  action: AlarmFormProps["action"];
  testId: string;
}) {
  return (
    <ActionForm
      action={action}
      submit={alarm ? "Save" : "Create"}
      testId={testId}
    >
      {alarm ? (
        <input
          type="hidden"
          name="enabled"
          value={alarm.ActionsEnabled === false ? "off" : "on"}
        />
      ) : (
        <Field
          label="Name"
          rule={PutCompositeAlarm.AlarmName}
          taken={taken}
          generate="name"
          unique
        >
          <input name="name" autoFocus />
        </Field>
      )}
      <Field label="Description" rule={PutCompositeAlarm.AlarmDescription}>
        <input name="description" defaultValue={alarm?.AlarmDescription} />
      </Field>
      <Field
        label="Rule"
        rule={PutCompositeAlarm.AlarmRule}
        hint='ALARM("cpu-high") AND NOT OK("latency")'
      >
        <textarea
          name="rule"
          rows={3}
          className="code-editor"
          required
          defaultValue={
            alarm?.AlarmRule ?? (alarms[0] ? `ALARM("${alarms[0]}")` : "")
          }
        />
      </Field>
      <ActionFields alarm={alarm} topics={topics} topicArn={topicArn} />
      <Field
        label="Actions suppressor"
        rule={PutCompositeAlarm.ActionsSuppressor}
        known={alarms}
      >
        <input
          name="suppressor"
          list={`${testId}-alarms`}
          defaultValue={alarm?.ActionsSuppressor}
        />
      </Field>
      <datalist id={`${testId}-alarms`}>
        {alarms.map((n) => (
          <option key={n} value={n} />
        ))}
      </datalist>
      <div className="form-grid">
        <Field
          label="Wait (s)"
          rule={{
            ...PutCompositeAlarm.ActionsSuppressorWaitPeriod,
            unit: "seconds",
          }}
        >
          <input
            name="wait"
            type="number"
            defaultValue={alarm?.ActionsSuppressorWaitPeriod ?? 60}
          />
        </Field>
        <Field
          label="Extension (s)"
          rule={{
            ...PutCompositeAlarm.ActionsSuppressorExtensionPeriod,
            unit: "seconds",
          }}
        >
          <input
            name="extension"
            type="number"
            defaultValue={alarm?.ActionsSuppressorExtensionPeriod ?? 60}
          />
        </Field>
      </div>
      {!alarm && (
        <Field label="Tags" rule={TAGS}>
          <textarea name="tags" rows={1} placeholder="team=payments" />
        </Field>
      )}
    </ActionForm>
  );
}
