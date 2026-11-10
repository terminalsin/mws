import { DescribeClusterCommand, DescribeClusterVersionsCommand, ListClustersCommand, ListNodegroupsCommand } from "@aws-sdk/client-eks";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AutoPick, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreateCluster } from "@mws-dashboard/ui/model/eks";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, eks } from "../../lib/clients";
import { clusterNetworks, rolesTrusting } from "../../lib/eks";
import { createCluster } from "./actions";

export const metadata: Metadata = { title: "EKS" };

const CLUSTER_NAME: Rule = { ...CreateCluster.name, hint: "Letters, digits, - and _, starting with a letter or digit", generate: "name" };

export default async function Clusters() {
  const [clusters, roles, networks, versions] = await Promise.all([
    load(async () => {
      const client = await eks();
      const names = (await client.send(new ListClustersCommand({}))).clusters ?? [];
      return Promise.all(
        names.map(async (name) => {
          const [c, groups] = await Promise.all([
            client.send(new DescribeClusterCommand({ name })).then((r) => r.cluster!),
            client.send(new ListNodegroupsCommand({ clusterName: name })).then(
              (r) => r.nodegroups ?? [],
              () => [],
            ),
          ]);
          return { c, groups };
        }),
      );
    }),
    load(() => rolesTrusting("eks.amazonaws.com")),
    load(clusterNetworks),
    load(async () => (await (await eks()).send(new DescribeClusterVersionsCommand({}))).clusterVersions ?? []),
  ]);
  const names = clusters.ok ? clusters.value.map(({ c }) => c.name!) : [];
  const usable = networks.ok ? networks.value.filter((n) => n.zones >= 2) : [];
  const fallback = versions.ok ? versions.value.find((v) => v.defaultVersion)?.clusterVersion : undefined;
  const vpc = (usable.find((n) => n.vpc.IsDefault) ?? usable[0])?.vpc.VpcId;
  const create = (
    <Sheet title="Create cluster" label="Create cluster" testId="create-eks-cluster">
      <ActionForm action={createCluster} submit="Create" testId="create-eks-cluster">
        <Field label="Name" rule={CLUSTER_NAME} taken={names} unique>
          <input name="name" autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Kubernetes version" rule={CreateCluster.version}>
            <select name="version" defaultValue="">
              <option value="">{fallback ? `Default (${fallback})` : "Default"}</option>
              {versions.ok &&
                versions.value.map((v) => (
                  <option key={v.clusterVersion} value={v.clusterVersion}>
                    {v.clusterVersion}
                    {v.versionStatus === "EXTENDED_SUPPORT" ? " · extended support" : ""}
                  </option>
                ))}
            </select>
          </Field>
          <Field label="VPC" member="resourcesVpcConfig">
            <select name="vpc" required defaultValue={vpc}>
              {networks.ok &&
                networks.value.map(({ vpc: v, zones }) => (
                  // EKS needs subnets in two Availability Zones: others show, but can't be picked.
                  <option key={v.VpcId} value={v.VpcId} disabled={zones < 2}>
                    {v.Tags?.find((t) => t.Key === "Name")?.Value ?? v.VpcId}
                    {zones < 2 ? ` · ${zones} AZ` : ""}
                  </option>
                ))}
            </select>
          </Field>
        </div>
        <AutoPick
          name="role"
          label="Cluster service role"
          creates="AmazonEKSClusterRole"
          options={roles.ok ? roles.value.map((r) => ({ value: r.Arn!, label: r.RoleName! })) : []}
          testId="cluster-role"
        />
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Clusters" actions={create}>
      {clusters.ok ? (
        <List
          label="Clusters"
          empty={<Empty icon={ICONS.eks} action={create} />}
          rows={clusters.value.map(({ c, groups }) => ({
            key: c.arn!,
            icon: <AwsIcon icon="brand/kubernetes" size={24} />,
            title: c.name,
            subtitle: c.endpoint ? <code className="clip">{c.endpoint}</code> : undefined,
            href: `/eks/cluster?name=${encodeURIComponent(c.name!)}`,
            meta: (
              <>
                <Pill>v{c.version}</Pill>
                {groups.length > 0 && <span>{groups.length} node groups</span>}
                <Status tone={STATUS_TONE(c.status)}>{c.status?.toLowerCase()}</Status>
                <span>{ago(c.createdAt)}</span>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={clusters.error} />
      )}
    </Page>
  );
}
