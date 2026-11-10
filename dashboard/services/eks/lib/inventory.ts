import "server-only";

import { DescribeClusterCommand } from "@aws-sdk/client-eks";
import type { InventoryItem } from "@mws-dashboard/aws";

import { eks } from "./clients";
import { clusterNames, nodegroups } from "./data";

const signalOf = (status: string | undefined, issues: number) =>
  issues ? { tone: "bad" as const, text: `${issues} health issues` } : status && /FAILED|DEGRADED/.test(status) ? { tone: "bad" as const, text: status.toLowerCase().replace(/_/g, " ") } : undefined;

export async function eksClusters(): Promise<InventoryItem[]> {
  const client = await eks();
  const names = await clusterNames();
  const items = await Promise.all(
    names.map(async (name) => {
      const [c, groups] = await Promise.all([client.send(new DescribeClusterCommand({ name })).then((r) => r.cluster!), nodegroups(name).catch(() => [])]);
      return [
        {
          service: "eks",
          type: "EKS cluster",
          id: c.arn ?? `eks:${name}`,
          name,
          href: `/eks/cluster?name=${encodeURIComponent(name)}`,
          detail: `Kubernetes ${c.version}`,
          tags: c.tags,
          signal: signalOf(c.status, c.health?.issues?.length ?? 0),
        },
        ...groups.map((g) => ({
          service: "eks",
          type: "EKS node group",
          id: g.nodegroupArn!,
          name: g.nodegroupName!,
          href: `/eks/nodegroup?cluster=${encodeURIComponent(name)}&name=${encodeURIComponent(g.nodegroupName!)}`,
          detail: `${name} · ${g.scalingConfig?.desiredSize ?? 0} × ${g.instanceTypes?.join(", ")}`,
          tags: g.tags,
          signal: signalOf(g.status, g.health?.issues?.length ?? 0),
        })),
      ];
    }),
  );
  return items.flat();
}
