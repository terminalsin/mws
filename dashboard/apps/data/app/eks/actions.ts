"use server";

import { CreateClusterCommand, CreateNodegroupCommand, DeleteClusterCommand, DeleteNodegroupCommand, UpdateNodegroupConfigCommand } from "@aws-sdk/client-eks";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { ROLES, roleFrom } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { eks } from "../../lib/clients";
import { subnetsOf } from "../../lib/eks";

export async function createCluster(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Cluster name");
    await (await eks()).send(
      new CreateClusterCommand({
        name,
        version: text(form, "version") || undefined,
        roleArn: await roleFrom(form, "role", ROLES.eksCluster),
        resourcesVpcConfig: { subnetIds: await subnetsOf(required(form, "vpc", "VPC")), endpointPublicAccess: true },
        accessConfig: { authenticationMode: "API_AND_CONFIG_MAP", bootstrapClusterCreatorAdminPermissions: true },
      }),
    );
    redirect(`/eks/cluster?name=${encodeURIComponent(name)}`);
  });
}

export async function deleteCluster(name: string) {
  return act(async () => {
    await (await eks()).send(new DeleteClusterCommand({ name }));
    redirect("/eks");
  });
}

export async function createNodegroup(cluster: string, subnets: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const size = Number(text(form, "size") || 2);
    await (await eks()).send(
      new CreateNodegroupCommand({
        clusterName: cluster,
        nodegroupName: required(form, "name", "Node group name"),
        nodeRole: await roleFrom(form, "role", ROLES.eksNode),
        subnets,
        instanceTypes: [text(form, "type") || "t3.medium"],
        scalingConfig: { minSize: Math.min(1, size), desiredSize: size, maxSize: Math.max(size, Number(text(form, "max") || size)) },
        capacityType: text(form, "spot") === "on" ? "SPOT" : "ON_DEMAND",
      }),
    );
    return "Node group creating";
  }, "/eks/cluster");
}

export async function scaleNodegroup(cluster: string, nodegroup: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const desiredSize = Number(required(form, "desired", "Desired size"));
    const maxSize = Math.max(desiredSize, Number(text(form, "max") || desiredSize));
    await (await eks()).send(new UpdateNodegroupConfigCommand({ clusterName: cluster, nodegroupName: nodegroup, scalingConfig: { desiredSize, maxSize, minSize: Math.min(desiredSize, Number(text(form, "min") || 0)) } }));
    return `Scaling to ${desiredSize}`;
  }, "/eks/cluster");
}

export async function deleteNodegroup(cluster: string, nodegroup: string) {
  return act(async () => {
    await (await eks()).send(new DeleteNodegroupCommand({ clusterName: cluster, nodegroupName: nodegroup }));
    return "Node group deleting";
  }, "/eks/cluster");
}
