import type { AwsSecurityFindingFilters, StringFilter } from "@aws-sdk/client-securityhub";

export interface FindingView {
  workflow?: string;
  record?: string;
  severity?: string;
  product?: string;
  resource?: string;
  compliance?: string;
}

const eq = (...values: string[]): StringFilter[] => values.map((Value) => ({ Value, Comparison: "EQUALS" }));

/** The ASFF filters a findings view asks for. By default it shows what the
 * Security Hub console does: active findings whose workflow is NEW or
 * NOTIFIED. `withSeverity: false` leaves the severity out, for the tiles. */
export function filters(v: FindingView, withSeverity = true): AwsSecurityFindingFilters {
  const workflow = v.workflow ?? "open";
  return {
    RecordState: v.record === "any" ? undefined : eq(v.record === "ARCHIVED" ? "ARCHIVED" : "ACTIVE"),
    WorkflowStatus: workflow === "open" ? eq("NEW", "NOTIFIED") : workflow === "any" ? undefined : eq(workflow),
    SeverityLabel: v.severity && withSeverity ? eq(v.severity) : undefined,
    ProductName: v.product ? eq(v.product) : undefined,
    ResourceType: v.resource ? eq(v.resource) : undefined,
    ComplianceStatus: v.compliance ? eq(v.compliance) : undefined,
  };
}

/** Readable lines for the filters an insight or rule holds. */
export function describeFilters(f: Record<string, unknown> | undefined): string[] {
  return Object.entries(f ?? {}).flatMap(([key, list]) =>
    Array.isArray(list)
      ? list.map((c: { Value?: unknown; Comparison?: string; Gte?: number; Lte?: number; Eq?: number; Key?: string; DateRange?: { Value?: number; Unit?: string } }) => {
          if (c.Value !== undefined) return `${key}${c.Key ? `.${c.Key}` : ""} ${(c.Comparison ?? "EQUALS").toLowerCase().replace(/_/g, " ")} ${String(c.Value)}`;
          if (c.Gte !== undefined || c.Lte !== undefined) return `${key} ${c.Gte ?? ""}–${c.Lte ?? ""}`;
          if (c.Eq !== undefined) return `${key} = ${c.Eq}`;
          if (c.DateRange) return `${key} in the last ${c.DateRange.Value} ${String(c.DateRange.Unit ?? "").toLowerCase()}`;
          return key;
        })
      : [],
  );
}
