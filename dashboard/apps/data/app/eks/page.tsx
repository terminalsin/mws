import { DescribeClusterCommand, ListClustersCommand, ListNodegroupsCommand } from "@aws-sdk/client-eks";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, eks } from "../../lib/clients";
import { rolesTrusting, vpcs } from "../../lib/eks";
import { createCluster } from "./actions";

export const metadata: Metadata = { title: "EKS" };

export default async function Clusters() {
  const [clusters, roles, networks] = await Promise.all([
    load(async () => {
      const client = await eks();
      const names = (await client.send(new ListClustersCommand({}))).clusters ?? [];
      return Promise.all(
        names.map(async (name) => {
          const [c, groups] = await Promise.all([
            client.send(new DescribeClusterCommand({ name })).then((r) => r.cluster!),
            client.send(new ListNodegroupsCommand({ clusterName: name })).then((r) => r.nodegroups ?? [], () => []),
          ]);
          return { c, groups };
        }),
      );
    }),
    load(() => rolesTrusting("eks.amazonaws.com")),
    load(vpcs),
  ]);
  const create = (
    <Sheet title="Create cluster" label="Create cluster" testId="create-eks-cluster">
      <ActionForm action={createCluster} submit="Create" testId="create-eks-cluster">
        <Field label="Name">
          <input name="name" required pattern="[A-Za-z0-9][A-Za-z0-9_\-]*" autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Kubernetes version">
            <select name="version" defaultValue="">
              <option value="">Default</option>
              {["1.33", "1.32", "1.31", "1.30"].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </Field>
          <Field label="VPC">
            <select name="vpc" required>
              {networks.ok && networks.value.map((v) => <option key={v.VpcId} value={v.VpcId}>{v.Tags?.find((t) => t.Key === "Name")?.Value ?? v.VpcId}</option>)}
            </select>
          </Field>
        </div>
        <Field label="Cluster service role">
          <input name="role" required list="eks-roles" defaultValue={roles.ok ? roles.value[0]?.Arn : undefined} />
        </Field>
        <datalist id="eks-roles">{roles.ok && roles.value.map((r) => <option key={r.Arn} value={r.Arn} />)}</datalist>
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
