"use server";

import {
  AssociateAccessPolicyCommand,
  CreateAccessEntryCommand,
  CreateAddonCommand,
  CreateClusterCommand,
  CreateFargateProfileCommand,
  CreateNodegroupCommand,
  DeleteAccessEntryCommand,
  DeleteAddonCommand,
  DeleteClusterCommand,
  DeleteFargateProfileCommand,
  DeleteNodegroupCommand,
  DisassociateAccessPolicyCommand,
  UpdateAddonCommand,
  UpdateClusterConfigCommand,
  UpdateClusterVersionCommand,
  UpdateNodegroupConfigCommand,
  UpdateNodegroupVersionCommand,
} from "@aws-sdk/client-eks";
import { FieldError, act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { ROLES, roleFrom } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { eks } from "../../lib/clients";
import { FARGATE_ROLE } from "../../lib/data";
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

const clusterPaths = ["/eks", "/eks/cluster", "/eks/nodegroup"];

/** One minor version up, as EKS allows (AWS: Upgrade version). */
export async function upgradeCluster(name: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const version = required(form, "version", "Kubernetes version");
      await fixable((c) => c.send(new UpdateClusterVersionCommand({ name, version, force: text(form, "force") === "on" || undefined })));
      return `Upgrading to ${version}`;
    },
    { revalidate: clusterPaths, fields: { version: "version", clusterName: "version" } },
  );
}

/** A node group to the cluster's version (or a newer AMI release). */
export async function upgradeNodegroup(cluster: string, nodegroup: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const version = text(form, "version") || undefined;
      await fixable((c) =>
        c.send(new UpdateNodegroupVersionCommand({ clusterName: cluster, nodegroupName: nodegroup, version, releaseVersion: text(form, "release") || undefined, force: text(form, "force") === "on" || undefined })),
      );
      return version ? `Upgrading to ${version}` : "Updating the AMI";
    },
    { revalidate: clusterPaths, fields: { version: "version", releaseVersion: "release" } },
  );
}

export async function createAddon(cluster: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const addonName = required(form, "addon", "Add-on");
      await fixable((c) =>
        c.send(
          new CreateAddonCommand({
            clusterName: cluster,
            addonName,
            addonVersion: text(form, "version") || undefined,
            serviceAccountRoleArn: text(form, "role") || undefined,
            configurationValues: text(form, "config") || undefined,
            resolveConflicts: "OVERWRITE",
          }),
        ),
      );
      return `Installing ${addonName}`;
    },
    { revalidate: clusterPaths, fields: { addonName: "addon", addonVersion: "version", serviceAccountRoleArn: "role", configurationValues: "config", ResourceInUseException: "addon" } },
  );
}

export async function updateAddon(cluster: string, addonName: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      await fixable((c) =>
        c.send(
          new UpdateAddonCommand({
            clusterName: cluster,
            addonName,
            addonVersion: text(form, "version") || undefined,
            configurationValues: form.has("config") ? text(form, "config") : undefined,
            serviceAccountRoleArn: text(form, "role") || undefined,
            resolveConflicts: "OVERWRITE",
          }),
        ),
      );
      return `Updating ${addonName}`;
    },
    { revalidate: clusterPaths, fields: { addonVersion: "version", configurationValues: "config", serviceAccountRoleArn: "role" } },
  );
}

export async function deleteAddon(cluster: string, addonName: string) {
  return act(async () => {
    await (await eks()).send(new DeleteAddonCommand({ clusterName: cluster, addonName }));
    return `Removing ${addonName}`;
  }, ...clusterPaths);
}

export async function createAccessEntry(cluster: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const principalArn = required(form, "principal", "IAM principal");
      const groups = text(form, "groups")
        .split(/[,\s]+/)
        .filter(Boolean);
      const client = await eks();
      await fixable((c) =>
        c.send(
          new CreateAccessEntryCommand({
            clusterName: cluster,
            principalArn,
            type: text(form, "type") || undefined,
            username: text(form, "username") || undefined,
            kubernetesGroups: groups.length ? groups : undefined,
          }),
        ),
      );
      const policyArn = text(form, "policy");
      if (policyArn) {
        const namespaces = text(form, "namespaces")
          .split(/[,\s]+/)
          .filter(Boolean);
        await client.send(
          new AssociateAccessPolicyCommand({
            clusterName: cluster,
            principalArn,
            policyArn,
            accessScope: namespaces.length ? { type: "namespace", namespaces } : { type: "cluster" },
          }),
        );
      }
      return `Granted ${principalArn.split("/").pop()}`;
    },
    { revalidate: clusterPaths, fields: { principalArn: "principal", kubernetesGroups: "groups", username: "username", ResourceInUseException: "principal" } },
  );
}

export async function associatePolicy(cluster: string, principalArn: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const policyArn = required(form, "policy", "Access policy");
      const namespaces = text(form, "namespaces")
        .split(/[,\s]+/)
        .filter(Boolean);
      await fixable((c) =>
        c.send(new AssociateAccessPolicyCommand({ clusterName: cluster, principalArn, policyArn, accessScope: namespaces.length ? { type: "namespace", namespaces } : { type: "cluster" } })),
      );
      return `Associated ${policyArn.split("/").pop()}`;
    },
    { revalidate: clusterPaths, fields: { policyArn: "policy", "accessScope.namespaces": "namespaces" } },
  );
}

export async function disassociatePolicy(cluster: string, principalArn: string, policyArn: string) {
  return act(async () => {
    await (await eks()).send(new DisassociateAccessPolicyCommand({ clusterName: cluster, principalArn, policyArn }));
    return `Removed ${policyArn.split("/").pop()}`;
  }, ...clusterPaths);
}

export async function deleteAccessEntry(cluster: string, principalArn: string) {
  return act(async () => {
    await (await eks()).send(new DeleteAccessEntryCommand({ clusterName: cluster, principalArn }));
    return "Access entry deleted";
  }, ...clusterPaths);
}

export async function createFargateProfile(cluster: string, subnets: string[], _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Profile name");
      const namespace = required(form, "namespace", "Namespace");
      const labels = Object.fromEntries(
        text(form, "labels")
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean)
          .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
      );
      await fixable(async (c) =>
        c.send(
          new CreateFargateProfileCommand({
            clusterName: cluster,
            fargateProfileName: name,
            podExecutionRoleArn: await roleFrom(form, "role", FARGATE_ROLE),
            subnets,
            selectors: [{ namespace, labels: Object.keys(labels).length ? labels : undefined }],
          }),
        ),
      );
      return `Creating ${name}`;
    },
    { revalidate: clusterPaths, fields: { fargateProfileName: "name", "selectors.namespace": "namespace", podExecutionRoleArn: "role", ResourceInUseException: "name" } },
  );
}

export async function deleteFargateProfile(cluster: string, name: string) {
  return act(async () => {
    await (await eks()).send(new DeleteFargateProfileCommand({ clusterName: cluster, fargateProfileName: name }));
    return `Deleting ${name}`;
  }, ...clusterPaths);
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
    { revalidate: ["/eks/cluster", "/eks/nodegroup"], fields: { "scalingConfig.minSize": "min", "scalingConfig.desiredSize": "desired", "scalingConfig.maxSize": "max" } },
  );
}

export async function deleteNodegroup(cluster: string, nodegroup: string, leave: boolean) {
  return act(async () => {
    await (await eks()).send(new DeleteNodegroupCommand({ clusterName: cluster, nodegroupName: nodegroup }));
    if (leave) redirect(`/eks/cluster?name=${encodeURIComponent(cluster)}&tab=compute`);
    return "Node group deleting";
  }, "/eks/cluster");
}

const LOG_TYPES = ["api", "audit", "authenticator", "controllerManager", "scheduler"] as const;

/** Endpoint access or control-plane logging (UpdateClusterConfig takes one
 * kind of change per call, as EKS's console sends them). */
export async function updateClusterConfig(name: string, kind: "endpoint" | "logging", _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const client = await eks();
      if (kind === "endpoint") {
        const endpointPublicAccess = text(form, "public") === "on";
        const endpointPrivateAccess = text(form, "private") === "on";
        if (!endpointPublicAccess && !endpointPrivateAccess) throw new FieldError("public", "Keep public or private access on");
        const cidrs = text(form, "cidrs")
          .split(/[,\s]+/)
          .filter(Boolean);
        await fixable((c) =>
          c.send(new UpdateClusterConfigCommand({ name, resourcesVpcConfig: { endpointPublicAccess, endpointPrivateAccess, publicAccessCidrs: endpointPublicAccess && cidrs.length ? cidrs : undefined } })),
        );
        return "Updating endpoint access";
      }
      const on = LOG_TYPES.filter((t) => text(form, t) === "on");
      const off = LOG_TYPES.filter((t) => !on.includes(t));
      await client.send(
        new UpdateClusterConfigCommand({
          name,
          logging: { clusterLogging: [...(on.length ? [{ types: [...on], enabled: true }] : []), ...(off.length ? [{ types: [...off], enabled: false }] : [])] },
        }),
      );
      return on.length ? `Logging ${on.join(", ")}` : "Logging off";
    },
    { revalidate: clusterPaths, fields: { publicAccessCidrs: "cidrs", "resourcesVpcConfig.publicAccessCidrs": "cidrs" } },
  );
}
