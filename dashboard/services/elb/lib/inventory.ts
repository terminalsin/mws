import "server-only";

import { DescribeLoadBalancersCommand as DescribeClassicCommand } from "@aws-sdk/client-elastic-load-balancing";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { classic } from "./clients";
import { lbHref, listLoadBalancers } from "./elb";

export async function loadBalancers(): Promise<InventoryItem[]> {
  const lbs = await listLoadBalancers();
  return lbs.map((l) => ({
    service: "elb",
    type: "Load balancer",
    id: l.LoadBalancerArn!,
    name: l.LoadBalancerName!,
    href: lbHref(l.LoadBalancerArn),
    detail: l.DNSName,
    signal: l.State?.Code === "failed" ? { tone: "bad" as const, text: "Failed" } : undefined,
  }));
}

export async function classicLoadBalancers(): Promise<InventoryItem[]> {
  const client = await classic();
  const lbs = await all(
    (Marker) => client.send(new DescribeClassicCommand({ Marker })),
    (r) => r.LoadBalancerDescriptions,
    (r) => r.NextMarker,
  );
  return lbs.map((l) => ({
    service: "elb",
    type: "Classic Load Balancer",
    id: `classic:${l.LoadBalancerName}`,
    name: l.LoadBalancerName!,
    href: `/elb/classic?name=${encodeURIComponent(l.LoadBalancerName!)}`,
    detail: l.DNSName,
  }));
}
