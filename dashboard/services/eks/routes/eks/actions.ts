"use server";

import { CreateClusterCommand, CreateNodegroupCommand, DeleteClusterCommand, DeleteNodegroupCommand, UpdateNodegroupConfigCommand } from "@aws-sdk/client-eks";
import { FieldError, act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { ROLES, roleFrom } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { eks } from "../../lib/clients";
import { clusterNetworks, fieldError } from "../../lib/eks";

// Form fields by API member, for messages that name one.
const NODEGROUP_FIELDS = { nodegroupName: "name", "scalingConfig.desiredSize": "size", "scalingConfig.maxSize": "max", instanceTypes: "type" };

/** Run a request, turning EKS's fixable rejections into field errors. */
async function fixable<T>(run: (client: Awaited<ReturnType<typeof eks>>) => Promise<T>): Promise<T> {
  const client = await eks();
  try {
    return await run(client);
  } catch (e) {
    throw fieldError(e);
  }
}

export async function createCluster(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Cluster name");
      const network = (await clusterNetworks()).find((n) => n.vpc.VpcId === required(form, "vpc", "VPC"));
      if (!network) throw new FieldError("vpc", "No longer exists", "missing");
      if (network.zones < 2) throw new FieldError("vpc", "Needs subnets in two Availability Zones");
      await fixable(async (c) =>
        c.send(
          new CreateClusterCommand({
            name,
            version: text(form, "version") || undefined,
            roleArn: await roleFrom(form, "role", ROLES.eksCluster),
            resourcesVpcConfig: { subnetIds: network.subnets, endpointPublicAccess: true },
            accessConfig: { authenticationMode: "API_AND_CONFIG_MAP", bootstrapClusterCreatorAdminPermissions: true },
          }),
        ),
      );
      redirect(`/eks/cluster?name=${encodeURIComponent(name)}`);
    },
    { fields: { clusterName: "name" } },
  );
}

export async function deleteCluster(name: string) {
  return act(async () => {
    await (await eks()).send(new DeleteClusterCommand({ name }));
    redirect("/eks");
  });
}

export async function createNodegroup(cluster: string, subnets: string[], _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const size = Number(text(form, "size") || 2);
      await fixable(async (c) =>
        c.send(
          new CreateNodegroupCommand({
            clusterName: cluster,
            nodegroupName: required(form, "name", "Node group name"),
            nodeRole: await roleFrom(form, "role", ROLES.eksNode),
            subnets,
            instanceTypes: [text(form, "type") || "t3.medium"],
            scalingConfig: { minSize: Math.min(1, size), desiredSize: size, maxSize: Number(text(form, "max") || size) },
            capacityType: text(form, "spot") === "on" ? "SPOT" : "ON_DEMAND",
          }),
        ),
      );
      return "Node group creating";
    },
    { revalidate: ["/eks/cluster"], fields: NODEGROUP_FIELDS },
  );
}

export async function scaleNodegroup(cluster: string, nodegroup: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const desiredSize = Number(required(form, "desired", "Desired size"));
      const maxSize = Number(required(form, "max", "Max size"));
      const minSize = Number(text(form, "min") || 0);
      await fixable(async (c) => c.send(new UpdateNodegroupConfigCommand({ clusterName: cluster, nodegroupName: nodegroup, scalingConfig: { desiredSize, maxSize, minSize } })));
      return `Scaling to ${desiredSize}`;
    },
    { revalidate: ["/eks/cluster"], fields: { "scalingConfig.minSize": "min", "scalingConfig.desiredSize": "desired", "scalingConfig.maxSize": "max" } },
  );
}

export async function deleteNodegroup(cluster: string, nodegroup: string) {
  return act(async () => {
    await (await eks()).send(new DeleteNodegroupCommand({ clusterName: cluster, nodegroupName: nodegroup }));
    return "Node group deleting";
  }, "/eks/cluster");
}
