import { DescribeClusterCommand, DescribeNodegroupCommand, ListAddonsCommand, ListNodegroupsCommand } from "@aws-sdk/client-eks";
import { load, region } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { Clock, Globe, Lock, Plus, Puzzle, SlidersHorizontal, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, eks } from "../../../lib/clients";
import { rolesTrusting } from "../../../lib/eks";
import { createNodegroup, deleteCluster, deleteNodegroup, scaleNodegroup } from "../actions";

export const metadata: Metadata = { title: "Cluster" };

type Props = { searchParams: Promise<{ name?: string }> };

export default async function Cluster({ searchParams }: Props) {
  const { name = "" } = await searchParams;
  const back = { href: "/eks", label: "Clusters" };
  const data = await load(async () => {
    const client = await eks();
    const [c, groupNames, addons, roles] = await Promise.all([
      client.send(new DescribeClusterCommand({ name })).then((r) => r.cluster!),
      client.send(new ListNodegroupsCommand({ clusterName: name })).then((r) => r.nodegroups ?? []),
      client.send(new ListAddonsCommand({ clusterName: name })).then((r) => r.addons ?? [], () => []),
      rolesTrusting("ec2.amazonaws.com").catch(() => []),
    ]);
    const groups = await Promise.all(groupNames.map((g) => client.send(new DescribeNodegroupCommand({ clusterName: name, nodegroupName: g })).then((r) => r.nodegroup!)));
    return { c, groups, addons, roles };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.eks} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { c, groups, addons, roles } = data.value;
  const subnets = c.resourcesVpcConfig?.subnetIds ?? [];
  return (
    <Page
      title={name}
      icon={ICONS.eks}
      back={back}
      subtitle={c.arn}
      actions={
        <>
          <Sheet title="Add node group" label="Add node group" icon={<Plus size={16} />} testId="create-nodegroup">
            <ActionForm action={createNodegroup.bind(null, name, subnets)} submit="Create" testId="create-nodegroup">
              <Field label="Name">
                <input name="name" required autoFocus />
              </Field>
              <Field label="Node IAM role">
                <input name="role" required list="node-roles" defaultValue={roles[0]?.Arn} />
              </Field>
              <datalist id="node-roles">
                {roles.map((r) => (
                  <option key={r.Arn} value={r.Arn} />
                ))}
              </datalist>
              <div className="form-row">
                <Field label="Instance type">
                  <input name="type" defaultValue="t3.medium" />
                </Field>
                <Field label="Desired size">
                  <input name="size" type="number" min={0} defaultValue={2} />
                </Field>
                <Field label="Max size">
                  <input name="max" type="number" min={1} defaultValue={3} />
                </Field>
              </div>
              <label className="check">
                <input type="checkbox" name="spot" /> Spot capacity
              </label>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteCluster.bind(null, name)} submit="Delete cluster" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-eks-cluster" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Kubernetes version", icon: <AwsIcon icon="brand/kubernetes" size={16} />, value: c.version },
          { label: "Status", icon: <AwsIcon icon={ICONS.eks} size={16} />, value: <Status tone={STATUS_TONE(c.status)}>{c.status?.toLowerCase()}</Status> },
          { label: "Endpoint access", icon: c.resourcesVpcConfig?.endpointPublicAccess ? <Globe size={15} /> : <Lock size={15} />, value: c.resourcesVpcConfig?.endpointPublicAccess ? "Public" : "Private" },
          c.resourcesVpcConfig?.vpcId && { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <a href={`/networking/vpc/${c.resourcesVpcConfig.vpcId}`}>{c.resourcesVpcConfig.vpcId}</a> },
          c.platformVersion && { label: "Platform version", icon: <Clock size={15} />, value: c.platformVersion },
        ]}
      />
      <Section title="Connect">
        <CodeBlock value={`aws eks update-kubeconfig --region ${await region()} --name ${name}\nkubectl get nodes`} label="kubeconfig" />
      </Section>
      <Section title="Node groups" count={groups.length} plain>
        <List
          label="Node groups"
          empty={<Empty icon={ICONS.eks} />}
          rows={groups.map((g) => ({
            key: g.nodegroupArn!,
            icon: <AwsIcon icon="resource/AmazonEC2Instances" size={22} />,
            title: g.nodegroupName,
            subtitle: `${g.instanceTypes?.join(", ")} · ${g.amiType}`,
            meta: (
              <>
                {g.capacityType === "SPOT" && <Pill tone="info">Spot</Pill>}
                <span title="Desired / max">
                  {g.scalingConfig?.desiredSize} / {g.scalingConfig?.maxSize}
                </span>
                <Status tone={STATUS_TONE(g.status)}>{g.status?.toLowerCase().replace(/_/g, " ")}</Status>
              </>
            ),
            actions: (
              <>
                <Sheet title={`Scale ${g.nodegroupName}`} label={`Scale ${g.nodegroupName}`} icon={<SlidersHorizontal size={15} />} testId={`scale-${g.nodegroupName}`}>
                  <ActionForm action={scaleNodegroup.bind(null, name, g.nodegroupName!)} submit="Update" testId={`scale-${g.nodegroupName}`}>
                    <div className="form-row">
                      <Field label="Min">
                        <input name="min" type="number" min={0} defaultValue={g.scalingConfig?.minSize} />
                      </Field>
                      <Field label="Desired">
                        <input name="desired" type="number" min={0} defaultValue={g.scalingConfig?.desiredSize} />
                      </Field>
                      <Field label="Max">
                        <input name="max" type="number" min={1} defaultValue={g.scalingConfig?.maxSize} />
                      </Field>
                    </div>
                  </ActionForm>
                </Sheet>
                <ActionForm action={deleteNodegroup.bind(null, name, g.nodegroupName!)} submit={`Delete ${g.nodegroupName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${g.nodegroupName}?`} />
              </>
            ),
          }))}
        />
      </Section>
      {addons.length > 0 && (
        <Section title="Add-ons">
          <div className="chips">
            {addons.map((a) => (
              <Pill key={a} icon={<Puzzle size={12} />}>
                {a}
              </Pill>
            ))}
          </div>
        </Section>
      )}
      <Tags tags={c.tags} />
    </Page>
  );
}
