import "server-only";

import { DescribeLoadBalancersCommand, DescribeTargetGroupsCommand, DescribeTargetHealthCommand, type TargetHealthDescription } from "@aws-sdk/client-elastic-load-balancing-v2";

import { elb } from "./clients";

export const HEALTH_TONE: Record<string, "good" | "warn" | "bad" | "neutral"> = {
  healthy: "good",
  initial: "warn",
  draining: "warn",
  unhealthy: "bad",
  unused: "neutral",
  unavailable: "neutral",
};

/** Healthy and total targets of a target group. */
export function healthCounts(targets: TargetHealthDescription[]) {
  return { healthy: targets.filter((t) => t.TargetHealth?.State === "healthy").length, total: targets.length };
}

export async function listTargetGroups() {
  const client = await elb();
  const groups = (await client.send(new DescribeTargetGroupsCommand({}))).TargetGroups ?? [];
  return Promise.all(
    groups.map(async (g) => ({
      group: g,
      targets: await client.send(new DescribeTargetHealthCommand({ TargetGroupArn: g.TargetGroupArn })).then(
        (r) => r.TargetHealthDescriptions ?? [],
        () => [],
      ),
    })),
  );
}

export async function listLoadBalancers() {
  return (await (await elb()).send(new DescribeLoadBalancersCommand({}))).LoadBalancers ?? [];
}
