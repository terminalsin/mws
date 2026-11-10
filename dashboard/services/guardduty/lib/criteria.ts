import type { Condition, FindingCriteria } from "@aws-sdk/client-guardduty";

import { BANDS } from "./clients";

export interface FindingFilters {
  view?: string;
  severity?: string;
  type?: string;
  resource?: string;
}

/** The finding criteria a findings view asks for: current or archived,
 * a severity band, a finding type, a resource type; merged over a saved
 * filter's own criteria. */
export function criteria(f: FindingFilters, base: FindingCriteria = {}, withSeverity = true): FindingCriteria {
  const c: Record<string, Condition> = { ...(base.Criterion ?? {}) };
  c["service.archived"] = { Equals: [f.view === "archived" ? "true" : "false"] };
  const band = BANDS.find((b) => b.id === f.severity);
  if (band && withSeverity) c.severity = { GreaterThanOrEqual: band.gte, LessThan: band.lt };
  if (f.type) c.type = { Equals: [f.type] };
  if (f.resource) c["resource.resourceType"] = { Equals: [f.resource] };
  return { Criterion: c };
}

const OPS: [keyof Condition, string][] = [
  ["Equals", "="],
  ["Eq", "="],
  ["NotEquals", "≠"],
  ["Neq", "≠"],
  ["GreaterThan", ">"],
  ["Gt", ">"],
  ["GreaterThanOrEqual", "≥"],
  ["Gte", "≥"],
  ["LessThan", "<"],
  ["Lt", "<"],
  ["LessThanOrEqual", "≤"],
  ["Lte", "≤"],
  ["Matches", "matches"],
  ["NotMatches", "doesn't match"],
];

/** A filter's criteria as readable lines: `type = Recon:EC2/Portscan`,
 * `severity ≥ 7`. Every attribute and operator, not just the type. */
export function describe(c: FindingCriteria | undefined): string[] {
  return Object.entries(c?.Criterion ?? {}).flatMap(([attr, cond]) =>
    OPS.flatMap(([op, sym]) => {
      const v = cond[op];
      if (v === undefined || v === null) return [];
      const text = Array.isArray(v) ? v.join(", ") : String(v);
      return [`${attr} ${sym} ${text}`];
    }),
  );
}
