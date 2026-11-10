import { DescribeClusterCommand, DescribeNodegroupCommand } from "@aws-sdk/client-eks";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { UpdateNodegroupConfig } from "@mws-dashboard/ui/model/eks";
import { ArrowUpCircle, Cpu, HardDrive, Layers, Shield, SlidersHorizontal, Trash2, TriangleAlert } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATUS_TONE, eks } from "../../../lib/clients";
import { updates as listUpdates } from "../../../lib/data";
import { Scaling } from "../../../lib/scaling.tsx";
import { deleteNodegroup, scaleNodegroup, upgradeNodegroup } from "../actions";
import { UpdateRows } from "../updates.tsx";

export const metadata: Metadata = { title: "Node group" };

type Props = { searchParams: Promise<{ cluster?: string; name?: string; tab?: string }> };

export default async function Nodegroup({ searchParams }: Props) {
  const { cluster = "", name = "", tab = "details" } = await searchParams;
  const back = { href: `/eks/cluster?name=${encodeURIComponent(cluster)}&tab=compute`, label: cluster };
  const here = `/eks/nodegroup?cluster=${encodeURIComponent(cluster)}&name=${encodeURIComponent(name)}`;
  const data = await load(async () => {
    const client = await eks();
    const [g, c, updates] = await Promise.all([
      client.send(new DescribeNodegroupCommand({ clusterName: cluster, nodegroupName: name })).then((r) => r.nodegroup!),
      client.send(new DescribeClusterCommand({ name: cluster })).then((r) => r.cluster!),
      listUpdates(cluster, { nodegroupName: name }),
    ]);
    return { g, c, updates };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.eks} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { g, c, updates } = data.value;
  const issues = g.health?.issues ?? [];
  const asgs = g.resources?.autoScalingGroups ?? [];
  const behind = !!g.version && g.version !== c.version;
  const active = g.status === "ACTIVE" || g.status === "DEGRADED";
  return (
    <Page
      title={name}
      icon={ICONS.eks}
      back={back}
      subtitle={g.nodegroupArn}
      actions={
        <>
          {active && (
            <Sheet title={behind ? "Upgrade version" : "Update AMI release"} label={behind ? "Upgrade version" : "Update AMI release"} icon={<ArrowUpCircle size={16} />} testId="upgrade-nodegroup">
              <ActionForm action={upgradeNodegroup.bind(null, cluster, name)} submit="Update" testId="upgrade-nodegroup">
                <Field label="Kubernetes version">
                  <select name="version" defaultValue={c.version}>
                    <option value={c.version}>
                      {behind ? `${g.version} → ${c.version}` : `${c.version} (current)`}
                    </option>
                  </select>
                </Field>
                <Field label="AMI release version" hint="Empty: the latest for the version">
                  <input name="release" spellCheck={false} placeholder={g.releaseVersion} />
                </Field>
                <label className="check">
                  <input type="checkbox" name="force" /> Force, even if pods can't be drained
                </label>
              </ActionForm>
            </Sheet>
          )}
          {active && (
            <Sheet title={`Scale ${name}`} label="Edit scaling" icon={<SlidersHorizontal size={16} />} testId="scale-nodegroup">
              <ActionForm action={scaleNodegroup.bind(null, cluster, name)} submit="Update" testId="scale-nodegroup">
                <Scaling
                  rules={UpdateNodegroupConfig.scalingConfig.fields!}
                  names={{ min: "min", desired: "desired", max: "max" }}
                  defaults={{ min: g.scalingConfig?.minSize, desired: g.scalingConfig?.desiredSize, max: g.scalingConfig?.maxSize }}
                />
              </ActionForm>
            </Sheet>
          )}
          <ActionForm action={deleteNodegroup.bind(null, cluster, name, true)} submit="Delete node group" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-nodegroup" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.eks} size={16} />, value: <Status tone={issues.length ? "bad" : STATUS_TONE(g.status)}>{g.status?.toLowerCase().replace(/_/g, " ") ?? ""}</Status> },
          { label: "Kubernetes version", icon: <AwsIcon icon="brand/kubernetes" size={16} />, value: behind ? <Pill tone="warn">{g.version} (cluster {c.version})</Pill> : g.version },
          { label: "Instance types", icon: <Cpu size={15} />, value: `${g.instanceTypes?.join(", ")}${g.capacityType === "SPOT" ? " · Spot" : ""}` },
          { label: "Scaling", icon: <Layers size={15} />, value: `${g.scalingConfig?.minSize} min · ${g.scalingConfig?.desiredSize} desired · ${g.scalingConfig?.maxSize} max` },
          g.diskSize && { label: "Disk", icon: <HardDrive size={15} />, value: `${g.diskSize} GiB` },
        ]}
      />
      {issues.length > 0 && (
        <div className="banner error" role="alert" data-testid="nodegroup-health">
          <TriangleAlert size={14} /> {issues.map((i) => `${i.code}: ${i.message}${i.resourceIds?.length ? ` (${i.resourceIds.join(", ")})` : ""}`).join("; ")}
        </div>
      )}
      <Segments
        label="Node group"
        items={[
          { label: "Details", href: here, active: tab === "details" },
          { label: "Update history", href: `${here}&tab=updates`, active: tab === "updates", count: updates.length || undefined },
          { label: "Kubernetes labels", href: `${here}&tab=labels`, active: tab === "labels" },
          { label: "Tags", href: `${here}&tab=tags`, active: tab === "tags" },
        ]}
      />
      {tab === "details" && (
        <>
          <Section>
            <Facts
              items={[
                ["AMI type", g.amiType],
                g.releaseVersion && ["AMI release version", g.releaseVersion],
                g.nodeRole && ["Node IAM role", <Link key="r" href={`/iam/roles/${g.nodeRole.split("/").pop()}`}>{g.nodeRole.split("/").pop()}</Link>],
                g.subnets?.length && ["Subnets", g.subnets.join(", ")],
                g.launchTemplate && ["Launch template", `${g.launchTemplate.name ?? g.launchTemplate.id} v${g.launchTemplate.version ?? "$Default"}`],
                g.remoteAccess?.ec2SshKey && ["SSH key", g.remoteAccess.ec2SshKey],
                g.resources?.remoteAccessSecurityGroup && [
                  "Remote access security group",
                  <Link key="s" href={`/ec2/group?id=${encodeURIComponent(g.resources.remoteAccessSecurityGroup)}`}>
                    <Pill icon={<Shield size={12} />}>{g.resources.remoteAccessSecurityGroup}</Pill>
                  </Link>,
                ],
                g.updateConfig && ["Max unavailable", g.updateConfig.maxUnavailable ?? `${g.updateConfig.maxUnavailablePercentage}%`],
                ["Created", when(g.createdAt)],
              ]}
            />
          </Section>
          <Section title="Auto Scaling groups" count={asgs.length} plain>
            <List
              label="Auto Scaling groups"
              empty={<Empty>No Auto Scaling group yet</Empty>}
              rows={asgs.map((a) => ({
                key: a.name!,
                icon: <AwsIcon icon="resource/AmazonEC2AutoScaling" size={22} />,
                title: a.name,
                href: `/autoscaling/group?name=${encodeURIComponent(a.name!)}`,
              }))}
            />
          </Section>
        </>
      )}
      {tab === "updates" && <UpdateRows updates={updates} empty />}
      {tab === "labels" && (
        <>
          {g.labels && Object.keys(g.labels).length ? <Tags tags={g.labels} /> : <Empty>No labels</Empty>}
          {g.taints?.length ? (
            <Section title="Taints" count={g.taints.length} plain>
              <List label="Taints" rows={g.taints.map((t) => ({ key: `${t.key}:${t.effect}`, title: `${t.key}${t.value ? `=${t.value}` : ""}`, meta: <Pill>{t.effect}</Pill> }))} />
            </Section>
          ) : null}
        </>
      )}
      {tab === "tags" && (g.tags && Object.keys(g.tags).length ? <Tags tags={g.tags} /> : <Empty>No tags</Empty>)}
    </Page>
  );
}
