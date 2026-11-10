import "server-only";

import { DescribeLoadBalancersCommand, DescribeTargetGroupsCommand, DescribeTargetHealthCommand, type TargetHealthDescription } from "@aws-sdk/client-elastic-load-balancing-v2";
import { all } from "@mws-dashboard/aws";

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

export async function allTargetGroups() {
  const client = await elb();
  return all(
    (Marker) => client.send(new DescribeTargetGroupsCommand({ Marker })),
    (r) => r.TargetGroups,
    (r) => r.NextMarker,
  );
}

export async function listTargetGroups() {
  const client = await elb();
  const groups = await allTargetGroups();
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
  const client = await elb();
  return all(
    (Marker) => client.send(new DescribeLoadBalancersCommand({ Marker })),
    (r) => r.LoadBalancers,
    (r) => r.NextMarker,
  );
}

export const lbHref = (arn: string | undefined) => `/elb/lb?arn=${encodeURIComponent(arn ?? "")}`;
export const tgHref = (arn: string | undefined) => `/elb/tg?arn=${encodeURIComponent(arn ?? "")}`;
export const listenerHref = (arn: string | undefined) => `/elb/listener?arn=${encodeURIComponent(arn ?? "")}`;
