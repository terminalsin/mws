import "server-only";

import {
  DescribeAddonCommand,
  DescribeFargateProfileCommand,
  DescribeNodegroupCommand,
  DescribeUpdateCommand,
  ListAccessEntriesCommand,
  ListAddonsCommand,
  ListAssociatedAccessPoliciesCommand,
  ListClustersCommand,
  ListFargateProfilesCommand,
  ListNodegroupsCommand,
  ListUpdatesCommand,
  type Update,
} from "@aws-sdk/client-eks";
import { all } from "@mws-dashboard/aws";
import type { RoleSpec } from "@mws-dashboard/aws/auto";

import { eks } from "./clients";

// Every List* here follows nextToken, so nothing stops at the first page.

export async function clusterNames() {
  const client = await eks();
  return all((nextToken) => client.send(new ListClustersCommand({ nextToken })), (r) => r.clusters, (r) => r.nextToken);
}

export async function nodegroups(clusterName: string) {
  const client = await eks();
  const names = await all((nextToken) => client.send(new ListNodegroupsCommand({ clusterName, nextToken })), (r) => r.nodegroups, (r) => r.nextToken);
  return Promise.all(names.map((nodegroupName) => client.send(new DescribeNodegroupCommand({ clusterName, nodegroupName })).then((r) => r.nodegroup!)));
}

export async function addons(clusterName: string) {
  const client = await eks();
  const names = await all((nextToken) => client.send(new ListAddonsCommand({ clusterName, nextToken })), (r) => r.addons, (r) => r.nextToken);
  return Promise.all(names.map((addonName) => client.send(new DescribeAddonCommand({ clusterName, addonName })).then((r) => r.addon!)));
}

export async function fargateProfiles(clusterName: string) {
  const client = await eks();
  const names = await all((nextToken) => client.send(new ListFargateProfilesCommand({ clusterName, nextToken })), (r) => r.fargateProfileNames, (r) => r.nextToken);
  return Promise.all(names.map((fargateProfileName) => client.send(new DescribeFargateProfileCommand({ clusterName, fargateProfileName })).then((r) => r.fargateProfile!)));
}

/** Access entries with the access policies associated with each. */
export async function accessEntries(clusterName: string) {
  const client = await eks();
  const arns = await all((nextToken) => client.send(new ListAccessEntriesCommand({ clusterName, nextToken })), (r) => r.accessEntries, (r) => r.nextToken);
  return Promise.all(
    arns.map(async (principalArn) => ({
      principalArn,
      policies: await all(
        (nextToken) => client.send(new ListAssociatedAccessPoliciesCommand({ clusterName, principalArn, nextToken })),
        (r) => r.associatedAccessPolicies,
        (r) => r.nextToken,
      ),
    })),
  );
}

/** A cluster's (or node group's or add-on's) updates, newest first. */
export async function updates(name: string, scope: { nodegroupName?: string; addonName?: string } = {}): Promise<Update[]> {
  const client = await eks();
  const ids = await all((nextToken) => client.send(new ListUpdatesCommand({ name, ...scope, nextToken })), (r) => r.updateIds, (r) => r.nextToken);
  const list = await Promise.all(ids.map((updateId) => client.send(new DescribeUpdateCommand({ name, updateId, ...scope })).then((r) => r.update!)));
  return list.sort((a, b) => (b.createdAt?.getTime() ?? 0) - (a.createdAt?.getTime() ?? 0));
}

/** The next minor Kubernetes version after `v` ("1.30" → "1.31"). */
export function nextMinor(v: string | undefined) {
  const [major, minor] = (v ?? "").split(".").map(Number);
  return Number.isFinite(minor) ? `${major}.${minor + 1}` : undefined;
}

/** Fargate's pod execution role, made on demand like the cluster and node roles. */
export const FARGATE_ROLE: RoleSpec = {
  name: "AmazonEKSFargatePodExecutionRole",
  service: "eks-fargate-pods.amazonaws.com",
  statements: [{ Effect: "Allow", Action: ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "logs:CreateLogStream", "logs:PutLogEvents"], Resource: "*" }],
};

export const UPDATE_TONE: Record<string, "good" | "warn" | "bad" | "neutral"> = { Successful: "good", InProgress: "warn", Failed: "bad", Cancelled: "neutral" };
