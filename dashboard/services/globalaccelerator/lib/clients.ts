import "server-only";

import { DescribeAddressesCommand, DescribeInstancesCommand, DescribeRegionsCommand, EC2Client } from "@aws-sdk/client-ec2";
import { DescribeLoadBalancersCommand, ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { GlobalAcceleratorClient } from "@aws-sdk/client-global-accelerator";
import { client } from "@mws-dashboard/aws";

export const ga = () => client(GlobalAcceleratorClient);

export const ICONS = {
  ga: "service/AWSGlobalAccelerator",
  region: "group/Region",
  alb: "resource/ElasticLoadBalancingApplicationLoadBalancer",
  nlb: "resource/ElasticLoadBalancingNetworkLoadBalancer",
  instance: "resource/AmazonEC2Instance",
  eip: "resource/AmazonVPCElasticNetworkInterface",
};

export const acceleratorHref = (arn: string | undefined) => `/ga/accelerator?arn=${encodeURIComponent(arn ?? "")}`;
export const groupHref = (arn: string | undefined) => `/ga/group?arn=${encodeURIComponent(arn ?? "")}`;

const FALLBACK_REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "eu-west-1", "eu-west-2", "eu-central-1", "eu-north-1", "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "sa-east-1"];

/** The Regions an endpoint group can be in (EC2's list, or AWS's main ones). */
export async function regions(): Promise<string[]> {
  try {
    const out = await (await client(EC2Client)).send(new DescribeRegionsCommand({}));
    const names = (out.Regions ?? []).map((r) => r.RegionName!).filter(Boolean);
    return names.length ? names.sort() : FALLBACK_REGIONS;
  } catch {
    return FALLBACK_REGIONS;
  }
}

/** What an endpoint group in `region` can point at: that Region's load
 * balancer ARNs, instance ids and EIP allocations (suggestions only, so a
 * failed lookup just offers nothing). */
export async function endpointCandidates(region: string): Promise<{ id: string; label: string }[]> {
  const quiet = <T,>(p: Promise<T[]>) => p.catch(() => [] as T[]);
  const [ec2, elb] = await Promise.all([client(EC2Client, { region }), client(ElasticLoadBalancingV2Client, { region })]);
  const [lbs, instances, eips] = await Promise.all([
    quiet(
      elb
        .send(new DescribeLoadBalancersCommand({}))
        .then((r) => (r.LoadBalancers ?? []).filter((l) => l.Type !== "gateway").map((l) => ({ id: l.LoadBalancerArn!, label: `${l.LoadBalancerName} (${l.Type})` }))),
    ),
    quiet(
      ec2
        .send(new DescribeInstancesCommand({ Filters: [{ Name: "instance-state-name", Values: ["pending", "running", "stopped"] }] }))
        .then((r) =>
          (r.Reservations ?? [])
            .flatMap((x) => x.Instances ?? [])
            .map((i) => ({ id: i.InstanceId!, label: i.Tags?.find((t) => t.Key === "Name")?.Value ?? i.InstanceId! })),
        ),
    ),
    quiet(ec2.send(new DescribeAddressesCommand({})).then((r) => (r.Addresses ?? []).flatMap((a) => (a.AllocationId ? [{ id: a.AllocationId, label: a.PublicIp ?? a.AllocationId }] : [])))),
  ]);
  return [...lbs, ...instances, ...eips];
}

/** Where an endpoint's own page is (load balancers and instances in the
 * console's Region). */
export function endpointHref(id: string | undefined, groupRegion: string | undefined, current: string): string | undefined {
  if (!id || groupRegion !== current) return undefined;
  if (id.includes(":loadbalancer/")) return `/elb/lb?arn=${encodeURIComponent(id)}`;
  if (id.startsWith("i-")) return `/ec2/instance?id=${id}`;
  return undefined;
}

export function endpointIcon(id: string | undefined) {
  if (id?.includes(":loadbalancer/net/")) return ICONS.nlb;
  if (id?.includes(":loadbalancer/")) return ICONS.alb;
  if (id?.startsWith("i-")) return ICONS.instance;
  return ICONS.eip;
}

export const endpointName = (id: string | undefined) => (id?.includes(":loadbalancer/") ? id.split("/").slice(-2, -1)[0] : id);

/** The accelerator's state as the console says it: disabled and deployed
 * are steady, anything else is still in progress. */
export function acceleratorState(a: { Enabled?: boolean; Status?: string }): { word: string; tone: "good" | "warn" | "neutral" } {
  if (a.Status && a.Status !== "DEPLOYED") return { word: "In progress", tone: "warn" };
  if (!a.Enabled) return { word: "Disabled", tone: "neutral" };
  return { word: "Deployed", tone: "good" };
}
