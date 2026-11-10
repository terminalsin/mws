import "server-only";

import { DescribeAutoScalingGroupsCommand } from "@aws-sdk/client-auto-scaling";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { autoscaling } from "./clients";

export async function groups(): Promise<InventoryItem[]> {
  const client = await autoscaling();
  const list = await all((NextToken) => client.send(new DescribeAutoScalingGroupsCommand({ NextToken })), (r) => r.AutoScalingGroups, (r) => r.NextToken);
  return list.map((g) => {
    const running = (g.Instances ?? []).filter((i) => i.LifecycleState === "InService").length;
    const unhealthy = (g.Instances ?? []).filter((i) => i.HealthStatus === "Unhealthy").length;
    const waiting = (g.Instances ?? []).filter((i) => i.LifecycleState?.endsWith(":Wait")).length;
    return {
      service: "autoscaling",
      type: "Auto Scaling group",
      id: g.AutoScalingGroupARN!,
      name: g.AutoScalingGroupName!,
      href: `/autoscaling/group?name=${encodeURIComponent(g.AutoScalingGroupName!)}`,
      detail: `${running}/${g.DesiredCapacity}`,
      tags: Object.fromEntries((g.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""])),
      signal: unhealthy
        ? { tone: "bad" as const, text: `${unhealthy} unhealthy` }
        : waiting
          ? { tone: "warn" as const, text: `${waiting} waiting on a lifecycle hook` }
          : g.SuspendedProcesses?.length
            ? { tone: "warn" as const, text: `${g.SuspendedProcesses.length} processes suspended` }
            : undefined,
    };
  });
}
