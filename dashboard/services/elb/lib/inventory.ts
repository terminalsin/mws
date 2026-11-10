import "server-only";

import { DescribeLoadBalancersCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { type InventoryItem } from "@mws-dashboard/aws";

import { elb } from "./clients";

export async function loadBalancers(): Promise<InventoryItem[]> {
  const out = await (await elb()).send(new DescribeLoadBalancersCommand({}));
  return (out.LoadBalancers ?? []).map((l) => ({
    service: "elb",
    type: "Load balancer",
    id: l.LoadBalancerArn!,
    name: l.LoadBalancerName!,
    href: `/elb/lb?arn=${encodeURIComponent(l.LoadBalancerArn!)}`,
    detail: l.DNSName,
    signal: l.State?.Code === "failed" ? { tone: "bad" as const, text: "Failed" } : undefined,
  }));
}
