import "server-only";

import {
  ListCidrCollectionsCommand,
  ListCidrLocationsCommand,
  ListGeoLocationsCommand,
  ListHealthChecksCommand,
  ListHostedZonesCommand,
  ListResourceRecordSetsCommand,
  ListTagsForResourcesCommand,
  type GeoLocationDetails,
  type HealthCheck,
  type ResourceRecordSet,
  type RRType,
} from "@aws-sdk/client-route-53";
import { all } from "@mws-dashboard/aws";

import { aliasTargets } from "./aliases";
import { route53 } from "./clients";
import type { Policy, RecordChoices, RecordDefaults } from "./record-fields";

// The Regions a latency record can name (Route 53's ResourceRecordSetRegion).
export const LATENCY_REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "ca-west-1", "sa-east-1", "mx-central-1",
  "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
  "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-7",
  "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-east-1", "me-south-1", "me-central-1", "il-central-1", "af-south-1",
];

export async function allHealthChecks(): Promise<HealthCheck[]> {
  const client = await route53();
  return all(
    (Marker) => client.send(new ListHealthChecksCommand({ Marker })),
    (r) => r.HealthChecks,
    (r) => (r.IsTruncated ? r.NextMarker : undefined),
  );
}

/** Name tags of health checks, by id (ListTagsForResources takes 10 at a time). */
export async function healthCheckNames(ids: string[]): Promise<Record<string, string>> {
  const client = await route53();
  const out: Record<string, string> = {};
  for (let i = 0; i < ids.length; i += 10) {
    const r = await client.send(new ListTagsForResourcesCommand({ ResourceType: "healthcheck", ResourceIds: ids.slice(i, i + 10) })).catch(() => null);
    for (const s of r?.ResourceTagSets ?? []) {
      const name = s.Tags?.find((t) => t.Key === "Name")?.Value;
      if (name && s.ResourceId) out[s.ResourceId] = name;
    }
  }
  return out;
}

/** "HTTPS example.com/health", "TCP 192.0.2.1:22", "Calculated (3)". */
export function healthCheckTarget(h: HealthCheck): string {
  const c = h.HealthCheckConfig!;
  const target = c.FullyQualifiedDomainName ?? c.IPAddress;
  if (c.Type?.startsWith("HTTP")) {
    const scheme = c.Type.startsWith("HTTPS") ? "https" : "http";
    const port = c.Port && c.Port !== (scheme === "https" ? 443 : 80) ? `:${c.Port}` : "";
    return `${scheme}://${target}${port}${c.ResourcePath ?? ""}`;
  }
  if (c.Type === "TCP") return `tcp://${target}:${c.Port}`;
  if (c.Type === "CALCULATED") return `Calculated · ${c.HealthThreshold ?? 0} of ${c.ChildHealthChecks?.length ?? 0} healthy`;
  if (c.Type === "CLOUDWATCH_METRIC") return `Alarm ${c.AlarmIdentifier?.Name ?? ""}`;
  return `${c.Type} ${target ?? ""}`;
}

export const geoValue = (g: { ContinentCode?: string; CountryCode?: string; SubdivisionCode?: string } | undefined) =>
  !g ? "" : g.SubdivisionCode ? `${g.CountryCode}/${g.SubdivisionCode}` : g.CountryCode ? g.CountryCode : g.ContinentCode ? `@${g.ContinentCode}` : "";

function geoLabel(g: GeoLocationDetails) {
  if (g.CountryCode === "*") return "Default";
  if (g.SubdivisionCode) return `${g.CountryName} · ${g.SubdivisionName}`;
  if (g.CountryCode) return g.CountryName ?? g.CountryCode;
  return g.ContinentName ?? g.ContinentCode ?? "";
}

/** "@EU" is a continent, "US" a country, "US/CA" a subdivision, "*" the default. */
export function parseGeo(value: string) {
  if (value.startsWith("@")) return { ContinentCode: value.slice(1) };
  const [CountryCode, SubdivisionCode] = value.split("/");
  return SubdivisionCode ? { CountryCode, SubdivisionCode } : { CountryCode };
}

/** Everything the record form offers: alias targets, health checks,
 * locations, Regions and CIDR collections. */
export async function recordChoices(zoneId: string, names: string[]): Promise<RecordChoices> {
  const client = await route53();
  const quiet = <T,>(p: Promise<T>, fallback: T) => p.catch(() => fallback);
  const [targets, checks, geos, collections] = await Promise.all([
    aliasTargets(zoneId, names),
    quiet(allHealthChecks(), []),
    quiet(
      (async () => {
        const out: GeoLocationDetails[] = [];
        let next: { StartContinentCode?: string; StartCountryCode?: string; StartSubdivisionCode?: string } = {};
        for (let i = 0; i < 50; i++) {
          const r = await client.send(new ListGeoLocationsCommand({ ...next, MaxItems: 100 }));
          out.push(...(r.GeoLocationDetailsList ?? []));
          if (!r.IsTruncated) break;
          next = { StartContinentCode: r.NextContinentCode, StartCountryCode: r.NextCountryCode, StartSubdivisionCode: r.NextSubdivisionCode };
        }
        return out;
      })(),
      [],
    ),
    quiet(
      all(
        (NextToken) => client.send(new ListCidrCollectionsCommand({ NextToken })),
        (r) => r.CidrCollections,
        (r) => r.NextToken,
      ),
      [],
    ),
  ]);
  const names2 = await quiet(healthCheckNames(checks.map((c) => c.Id!)), {} as Record<string, string>);
  const cidr = await Promise.all(
    collections.map(async (c) => ({
      id: c.Id!,
      name: c.Name ?? c.Id!,
      locations: await quiet(
        all(
          (NextToken) => client.send(new ListCidrLocationsCommand({ CollectionId: c.Id!, NextToken })),
          (r) => r.CidrLocations?.map((l) => l.LocationName!),
          (r) => r.NextToken,
        ),
        [] as string[],
      ),
    })),
  );
  const sortedGeos = geos.length ? geos : [{ CountryCode: "*", CountryName: "Default" }];
  return {
    targets,
    healthChecks: checks.map((h) => ({ id: h.Id!, label: names2[h.Id!] ? `${names2[h.Id!]} · ${healthCheckTarget(h)}` : healthCheckTarget(h) })),
    geos: sortedGeos.map((g) => ({ value: geoValue(g) || "*", label: geoLabel(g) })),
    regions: LATENCY_REGIONS,
    cidr,
  };
}

export function policyOf(r: ResourceRecordSet | undefined): Policy {
  if (!r) return "simple";
  if (r.Weight !== undefined) return "weighted";
  if (r.Region) return "latency";
  if (r.Failover) return "failover";
  if (r.GeoLocation) return "geo";
  if (r.MultiValueAnswer !== undefined) return "multivalue";
  if (r.CidrRoutingConfig) return "cidr";
  return "simple";
}

export const recordName = (n: string | undefined) => (n ?? "").replace(/\.$/, "").replace(/\\052/g, "*");

export function recordDefaults(r: ResourceRecordSet | undefined, domain: string): RecordDefaults {
  return {
    name: r ? recordName(r.Name) : domain,
    type: r?.Type ?? "A",
    values: r?.ResourceRecords?.map((v) => v.Value).join("\n") ?? "",
    ttl: r?.TTL ?? 300,
    alias: r?.AliasTarget?.DNSName?.replace(/\.$/, ""),
    aliasZone: r?.AliasTarget?.HostedZoneId?.split("/").pop(),
    evaluate: r?.AliasTarget?.EvaluateTargetHealth,
    policy: policyOf(r),
    setId: r?.SetIdentifier,
    weight: r?.Weight !== undefined ? Number(r.Weight) : undefined,
    region: r?.Region,
    failover: r?.Failover,
    geo: r?.GeoLocation ? geoValue(r.GeoLocation) || "*" : undefined,
    healthCheck: r?.HealthCheckId,
    cidrCollection: r?.CidrRoutingConfig?.CollectionId,
    cidrLocation: r?.CidrRoutingConfig?.LocationName,
  };
}

/** What a record's routing policy says, for its row. */
export function routingSummary(r: ResourceRecordSet, geoLabels?: Map<string, string>): string | null {
  switch (policyOf(r)) {
    case "weighted":
      return `weight ${r.Weight}`;
    case "latency":
      return r.Region ?? null;
    case "failover":
      return r.Failover === "PRIMARY" ? "primary" : "secondary";
    case "geo": {
      const v = geoValue(r.GeoLocation) || "*";
      return geoLabels?.get(v) ?? (v === "*" ? "default location" : v.replace(/^@/, ""));
    }
    case "multivalue":
      return "multivalue";
    case "cidr":
      return `CIDR ${r.CidrRoutingConfig?.LocationName}`;
    default:
      return null;
  }
}

/** Every record set of a zone (ListResourceRecordSets pages by name, type
 * and set identifier rather than a token). */
export async function allRecords(zoneId: string): Promise<ResourceRecordSet[]> {
  const client = await route53();
  const out: ResourceRecordSet[] = [];
  let start: { StartRecordName?: string; StartRecordType?: RRType; StartRecordIdentifier?: string } = {};
  for (let i = 0; i < 100; i++) {
    const r = await client.send(new ListResourceRecordSetsCommand({ HostedZoneId: zoneId, ...start }));
    out.push(...(r.ResourceRecordSets ?? []));
    if (!r.IsTruncated) break;
    start = { StartRecordName: r.NextRecordName, StartRecordType: r.NextRecordType, StartRecordIdentifier: r.NextRecordIdentifier };
  }
  return out;
}

/** The record sets, across the account's zones, that use health check `id`. */
export async function recordsUsing(id: string) {
  const client = await route53();
  const zones = await all(
    (Marker) => client.send(new ListHostedZonesCommand({ Marker })),
    (r) => r.HostedZones,
    (r) => (r.IsTruncated ? r.NextMarker : undefined),
  );
  const per = await Promise.all(zones.map(async (z) => (await allRecords(z.Id!).catch(() => [])).filter((r) => r.HealthCheckId === id).map((r) => ({ zone: z, record: r }))));
  return per.flat();
}
