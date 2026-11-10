import "server-only";

import {
  ListMetricsCommand,
  type MetricAlarm,
} from "@aws-sdk/client-cloudwatch";
import { all, frameInfo, load } from "@mws-dashboard/aws";

import { OP, period } from "./alarm-form";
import { cloudwatch, dimsText, topicArns, type AnyAlarm } from "./clients";

/** "Sum(Orders) > 100 for 2 × 1 min": the alarm's rule as one line. */
export function rule(a: AnyAlarm): string {
  if (a.kind === "composite") return a.AlarmRule ?? "";
  if (a.kind === "log") {
    const q = a.ScheduledQueryConfiguration;
    return `${q?.AggregationExpression ?? "query"} ${OP[a.ComparisonOperator ?? ""] ?? a.ComparisonOperator} ${a.Threshold} · ${q?.ScheduleConfiguration?.ScheduleExpression ?? ""}`;
  }
  return metricRule(a);
}

export function metricRule(a: MetricAlarm) {
  const times =
    (a.EvaluationPeriods ?? 1) > 1
      ? `${a.DatapointsToAlarm ?? a.EvaluationPeriods}/${a.EvaluationPeriods} × `
      : "";
  const cmp = OP[a.ComparisonOperator ?? ""] ?? a.ComparisonOperator;
  if (!a.MetricName) {
    const shown = a.Metrics?.find((m) => m.Id === a.ThresholdMetricId)
      ? a.Metrics.find(
          (m) => m.ReturnData !== false && m.Id !== a.ThresholdMetricId,
        )
      : a.Metrics?.find((m) => m.ReturnData !== false);
    const expr =
      shown?.Expression ??
      (shown?.MetricStat
        ? `${shown.MetricStat.Stat}(${shown.MetricStat.Metric?.MetricName})`
        : `${a.Metrics?.length ?? 0} metrics`);
    const p = shown?.Period ?? shown?.MetricStat?.Period;
    return a.ThresholdMetricId
      ? `${expr} ${cmp} band ${a.ThresholdMetricId} · ${times}${period(p)}`
      : `${expr} ${cmp} ${a.Threshold} · ${times}${period(p)}`;
  }
  return `${a.Statistic ?? a.ExtendedStatistic}(${a.MetricName}) ${cmp} ${a.Threshold} · ${times}${period(a.Period)}`;
}

/** What the alarm forms suggest: namespaces, metric names, dimensions and topics. */
export async function formOptions() {
  const [metrics, topics, info] = await Promise.all([
    load(async () => {
      const c = await cloudwatch();
      return all(
        (NextToken) => c.send(new ListMetricsCommand({ NextToken })),
        (r) => r.Metrics,
        (r) => r.NextToken,
      );
    }),
    load(topicArns),
    frameInfo(),
  ]);
  const list = metrics.ok ? metrics.value : [];
  return {
    namespaces: [...new Set(list.map((m) => m.Namespace!))].sort(),
    names: [...new Set(list.map((m) => m.MetricName!))].sort(),
    dims: [...new Set(list.map((m) => dimsText(m.Dimensions)).filter(Boolean))],
    topics: topics.ok ? topics.value : [],
    topicArn: info.account
      ? `arn:aws:sns:${info.region}:${info.account}:{}`
      : undefined,
  };
}
