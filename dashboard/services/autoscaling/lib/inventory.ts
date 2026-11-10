import "server-only";

import { DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { type InventoryItem } from "@mws-dashboard/aws";

import { autoscaling } from "./clients";

export async function groups(): Promise<InventoryItem[]> {
  const out = await (await autoscaling()).send(new DescribeAutoScalingGroupsCommand({}));
  return (out.AutoScalingGroups ?? []).map((g) => {
    const running = (g.Instances ?? []).filter((i) => i.LifecycleState === "InService").length;
    const unhealthy = (g.Instances ?? []).filter((i) => i.HealthStatus === "Unhealthy").length;
    return {
      service: "autoscaling",
      type: "Auto Scaling group",
      id: g.AutoScalingGroupARN!,
      name: g.AutoScalingGroupName!,
      href: `/autoscaling/group?name=${encodeURIComponent(g.AutoScalingGroupName!)}`,
      detail: `${running}/${g.DesiredCapacity}`,
      tags: Object.fromEntries((g.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""])),
      signal: unhealthy ? { tone: "bad" as const, text: `${unhealthy} unhealthy` } : undefined,
    };
  });
}
