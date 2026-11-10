import "server-only";

import { CloudWatchClient, GetMetricDataCommand, type MetricDataQuery } from "@aws-sdk/client-cloudwatch";
import { ListRequestedServiceQuotaChangeHistoryCommand, type RequestedServiceQuotaChange, type ServiceQuota } from "@aws-sdk/client-service-quotas";
import { all, client } from "@mws-dashboard/aws";

import { quotas } from "./clients";

/** Request statuses that are still open: the page follows them until settled. */
export const OPEN = new Set(["PENDING", "CASE_OPENED"]);

export const STATUS_TONE: Record<string, "good" | "bad" | "info" | "neutral"> = {
  APPROVED: "good",
  DENIED: "bad",
  INVALID_REQUEST: "bad",
  NOT_APPROVED: "bad",
  CASE_CLOSED: "neutral",
  PENDING: "info",
  CASE_OPENED: "info",
};

export const statusWord = (s: string | undefined) => (s ?? "").toLowerCase().replace(/_/g, " ");

/** Open requests of a service, by quota code. */
export async function openRequests(service: string): Promise<Map<string, RequestedServiceQuotaChange>> {
  const c = await quotas();
  const lists = await Promise.all(
    [...OPEN].map((Status) =>
      all(
        (NextToken) => c.send(new ListRequestedServiceQuotaChangeHistoryCommand({ ServiceCode: service, Status: Status as "PENDING", NextToken })),
        (r) => r.RequestedQuotas,
        (r) => r.NextToken,
      ),
    ),
  );
  return new Map(lists.flat().map((r) => [r.QuotaCode!, r]));
}

/** Current usage of each quota with a `UsageMetric` (AWS/Usage in
 * CloudWatch): the latest value of the recommended statistic over the last
 * hour, by quota code. */
export async function usage(list: ServiceQuota[]): Promise<Map<string, number>> {
  const metered = list.filter((q) => q.UsageMetric?.MetricName && q.UsageMetric.MetricNamespace);
  if (!metered.length) return new Map();
  const cw = await client(CloudWatchClient);
  const queries: MetricDataQuery[] = metered.map((q, i) => ({
    Id: `q${i}`,
    MetricStat: {
      Metric: {
        Namespace: q.UsageMetric!.MetricNamespace,
        MetricName: q.UsageMetric!.MetricName,
        Dimensions: Object.entries(q.UsageMetric!.MetricDimensions ?? {}).map(([Name, Value]) => ({ Name, Value })),
      },
      Period: 300,
      Stat: q.UsageMetric!.MetricStatisticRecommendation || "Maximum",
    },
  }));
  const out = new Map<string, number>();
  const end = new Date();
  const start = new Date(end.getTime() - 3_600_000);
  for (let i = 0; i < queries.length; i += 500) {
    const r = await cw.send(new GetMetricDataCommand({ MetricDataQueries: queries.slice(i, i + 500), StartTime: start, EndTime: end, ScanBy: "TimestampDescending" }));
    for (const res of r.MetricDataResults ?? []) {
      const q = metered[Number(res.Id!.slice(1))];
      if (res.Values?.length) out.set(q.QuotaCode!, res.Values[0]);
    }
  }
  return out;
}

export function utilization(used: number | undefined, value: number | undefined) {
  if (used === undefined || !value) return undefined;
  return Math.round((used / value) * 1000) / 10;
}

export const tone = (pct: number | undefined) => (pct === undefined ? "neutral" : pct >= 90 ? "bad" : pct >= 80 ? "warn" : "good");
