import "server-only";

import { DescribeLoadBalancersCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { ListAcceleratorsCommand } from "@aws-sdk/client-global-accelerator";
import { all, region } from "@mws-dashboard/aws";

import { elbv2, ga } from "./clients";
import type { AliasTarget } from "./record-fields";

// The hosted zones AWS publishes for alias targets outside Route 53.
export const CLOUDFRONT_ZONE = "Z2FDTNDATAQYW2";
export const GLOBAL_ACCELERATOR_ZONE = "Z2BJ6XQ5FK7U4H";
const S3_WEBSITE_ZONE: Record<string, string> = {
  "us-east-1": "Z3AQBSTGFYJSTF",
  "us-east-2": "Z2O1EMRO9K5GLX",
  "us-west-1": "Z2F56UZL2M1ACD",
  "us-west-2": "Z3BJ6K6RIION7M",
  "ca-central-1": "Z1QDHH18159H29",
  "eu-west-1": "Z1BKCTXD74EZPE",
  "eu-west-2": "Z3GKZC51ZF0DB4",
  "eu-west-3": "Z3R1K369G5AVDG",
  "eu-central-1": "Z21DNDUVLTQW6Q",
  "eu-north-1": "Z3BAZG2TWCNX0D",
  "ap-south-1": "Z11RGJOFQNVJUP",
  "ap-southeast-1": "Z3O0J2DXBE1FTB",
  "ap-southeast-2": "Z1WCIGYICN2BYD",
  "ap-northeast-1": "Z2M4EHUR26P7ZW",
  "ap-northeast-2": "Z3W03O7B5YMIYP",
  "sa-east-1": "Z7KQH4QJS55SO",
};

/** What an alias in this zone can point at: the Region's load balancers
 * (with their canonical hosted zone), accelerators, the Region's S3 website
 * endpoint, and the zone's own records. Suggestions only: a failed lookup
 * offers nothing. */
export async function aliasTargets(zoneId: string, names: string[]): Promise<AliasTarget[]> {
  const quiet = <T,>(p: Promise<T[]>) => p.catch(() => [] as T[]);
  const r = await region();
  const [lbs, accelerators] = await Promise.all([
    quiet(
      elbv2().then((c) =>
        all(
          (Marker) => c.send(new DescribeLoadBalancersCommand({ Marker })),
          (x) => x.LoadBalancers,
          (x) => x.NextMarker,
        ),
      ),
    ),
    quiet(
      ga().then((c) =>
        all(
          (NextToken) => c.send(new ListAcceleratorsCommand({ NextToken })),
          (x) => x.Accelerators,
          (x) => x.NextToken,
        ),
      ),
    ),
  ]);
  const out: AliasTarget[] = [];
  for (const l of lbs) {
    if (!l.CanonicalHostedZoneId || !l.DNSName) continue;
    out.push({ group: "Load balancers", label: l.LoadBalancerName!, dns: l.DNSName, zone: l.CanonicalHostedZoneId, health: true });
  }
  for (const a of accelerators) {
    if (a.DnsName) out.push({ group: "Global Accelerator", label: a.Name!, dns: a.DnsName, zone: GLOBAL_ACCELERATOR_ZONE, health: false });
    if (a.DualStackDnsName) out.push({ group: "Global Accelerator", label: `${a.Name} (dual-stack)`, dns: a.DualStackDnsName, zone: GLOBAL_ACCELERATOR_ZONE, health: false });
  }
  if (S3_WEBSITE_ZONE[r]) out.push({ group: "S3 website", label: `S3 website (${r})`, dns: `s3-website-${r}.amazonaws.com`, zone: S3_WEBSITE_ZONE[r], health: false });
  for (const n of names) out.push({ group: "This zone", label: n, dns: n, zone: zoneId, health: true });
  return out;
}

/** The kind of target an alias points at, for its row and link. */
export function aliasKind(zone: string | undefined, dns: string | undefined, ownZone: string): { label: string; href?: string } {
  const z = (zone ?? "").split("/").pop();
  const d = (dns ?? "").replace(/\.$/, "").toLowerCase();
  if (z === ownZone) return { label: "Record" };
  if (z === CLOUDFRONT_ZONE) return { label: "CloudFront" };
  if (z === GLOBAL_ACCELERATOR_ZONE) return { label: "Accelerator", href: "/ga" };
  if (Object.values(S3_WEBSITE_ZONE).includes(z ?? "")) return { label: "S3 website", href: "/s3" };
  if (d.endsWith(".elb.amazonaws.com")) return { label: "Load balancer", href: "/elb" };
  return { label: "Alias" };
}
