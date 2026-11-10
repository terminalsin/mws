import type { Expression, Granularity, GroupDefinition } from "@aws-sdk/client-cost-explorer";

/** A cost and usage report as the page's search parameters carry it. */
export interface Query {
  start: string;
  end: string;
  granularity: Granularity;
  metric: string;
  /** "DIMENSION:SERVICE", "TAG:env", "COST_CATEGORY:Teams". */
  groups: string[];
  filter?: string;
  values: string[];
  exclude: boolean;
}

export const METRICS: Record<string, string> = {
  UnblendedCost: "Unblended costs",
  AmortizedCost: "Amortized costs",
  BlendedCost: "Blended costs",
  NetUnblendedCost: "Net unblended costs",
  NetAmortizedCost: "Net amortized costs",
  UsageQuantity: "Usage quantity",
  NormalizedUsageAmount: "Normalized usage amount",
};

export const DIMENSIONS: Record<string, string> = {
  SERVICE: "Service",
  LINKED_ACCOUNT: "Linked account",
  REGION: "Region",
  USAGE_TYPE: "Usage type",
  USAGE_TYPE_GROUP: "Usage type group",
  OPERATION: "API operation",
  INSTANCE_TYPE: "Instance type",
  PURCHASE_TYPE: "Purchase option",
  RECORD_TYPE: "Charge type",
  PLATFORM: "Platform",
  AZ: "Availability Zone",
};

export function parseQuery(p: Record<string, string | string[] | undefined>, defaults: { start: string; end: string }): Query {
  const one = (k: string) => (Array.isArray(p[k]) ? p[k][0] : p[k]) || undefined;
  const many = (k: string) => (Array.isArray(p[k]) ? p[k] : p[k] ? [p[k]] : []).filter(Boolean) as string[];
  const g = one("granularity");
  return {
    start: one("start") ?? defaults.start,
    end: one("end") ?? defaults.end,
    granularity: g === "DAILY" || g === "HOURLY" ? g : "MONTHLY",
    metric: one("metric") && METRICS[one("metric")!] ? one("metric")! : "UnblendedCost",
    groups: p.group === undefined ? ["DIMENSION:SERVICE"] : [...new Set(many("group"))].slice(0, 2),
    filter: one("filter"),
    values: (one("values") ?? "")
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean),
    exclude: one("exclude") === "on",
  };
}

export function split(key: string): { type: "DIMENSION" | "TAG" | "COST_CATEGORY"; key: string } {
  const i = key.indexOf(":");
  const type = key.slice(0, i) as "DIMENSION" | "TAG" | "COST_CATEGORY";
  return { type: ["DIMENSION", "TAG", "COST_CATEGORY"].includes(type) ? type : "DIMENSION", key: key.slice(i + 1) };
}

export function groupBy(q: Query): GroupDefinition[] | undefined {
  return q.groups.length ? q.groups.map((g) => ({ Type: split(g).type, Key: split(g).key })) : undefined;
}

export function filterOf(q: Query): Expression | undefined {
  if (!q.filter || !q.values.length) return undefined;
  const { type, key } = split(q.filter);
  const e: Expression =
    type === "TAG" ? { Tags: { Key: key, Values: q.values } } : type === "COST_CATEGORY" ? { CostCategories: { Key: key, Values: q.values } } : { Dimensions: { Key: key as never, Values: q.values } };
  return q.exclude ? { Not: e } : e;
}

/** Hourly reports take timestamps, the others dates. */
export function period(q: Query) {
  return q.granularity === "HOURLY" ? { Start: `${q.start}T00:00:00Z`, End: `${q.end}T00:00:00Z` } : { Start: q.start, End: q.end };
}

export function label(key: string): string {
  const { type, key: k } = split(key);
  return type === "DIMENSION" ? (DIMENSIONS[k] ?? k) : type === "TAG" ? `Tag: ${k}` : `Cost category: ${k}`;
}

/** The report's URL, for links from other pages (an anomaly's service). */
export function href(q: Partial<Query>): string {
  const s = new URLSearchParams();
  if (q.start) s.set("start", q.start);
  if (q.end) s.set("end", q.end);
  if (q.granularity) s.set("granularity", q.granularity);
  if (q.metric) s.set("metric", q.metric);
  for (const g of q.groups ?? []) s.append("group", g);
  if (q.filter) s.set("filter", q.filter);
  if (q.values?.length) s.set("values", q.values.join(","));
  if (q.exclude) s.set("exclude", "on");
  return `/ce?${s}`;
}
