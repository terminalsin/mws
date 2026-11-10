import type { HealthCheck, HealthCheckObservation } from "@aws-sdk/client-route-53";

import type { HealthDefaults, HealthKind } from "./health-fields";

export const CHECKER_REGIONS = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "sa-east-1"];

/** Route 53 calls an endpoint healthy when more than 18% of its checkers
 * report success. */
export function healthOf(observations: HealthCheckObservation[]): { word: "Healthy" | "Unhealthy" | "Unknown"; tone: "good" | "bad" | "neutral"; healthy: number; total: number } {
  const total = observations.length;
  const healthy = observations.filter((o) => o.StatusReport?.Status?.startsWith("Success")).length;
  if (total === 0) return { word: "Unknown", tone: "neutral", healthy, total };
  return healthy / total > 0.18 ? { word: "Healthy", tone: "good", healthy, total } : { word: "Unhealthy", tone: "bad", healthy, total };
}

export function healthDefaults(h: HealthCheck, name?: string): HealthDefaults {
  const c = h.HealthCheckConfig!;
  const kind: HealthKind = c.Type === "TCP" ? "TCP" : c.Type === "CALCULATED" ? "CALCULATED" : c.Type === "CLOUDWATCH_METRIC" ? "CLOUDWATCH_METRIC" : "http";
  const host = c.FullyQualifiedDomainName ?? (c.IPAddress?.includes(":") ? `[${c.IPAddress}]` : c.IPAddress);
  const https = c.Type?.startsWith("HTTPS");
  const port = c.Port && c.Port !== (https ? 443 : 80) ? `:${c.Port}` : "";
  return {
    name,
    kind,
    url: kind === "http" ? `${https ? "https" : "http"}://${host}${port}${c.ResourcePath ?? "/"}` : undefined,
    host: c.FullyQualifiedDomainName ?? c.IPAddress,
    port: c.Port,
    search: c.SearchString,
    interval: c.RequestInterval,
    threshold: c.FailureThreshold,
    regions: c.Regions,
    inverted: c.Inverted,
    disabled: c.Disabled,
    children: c.ChildHealthChecks,
    healthThreshold: c.HealthThreshold,
    alarm: c.AlarmIdentifier?.Name,
    alarmRegion: c.AlarmIdentifier?.Region,
    insufficient: c.InsufficientDataHealthStatus,
  };
}
