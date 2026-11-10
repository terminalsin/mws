import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { LINKS, nameTag } from "./clients";
import { describeRule, listGroups, listImages, listInstances, listRules, listTemplates, listVolumes } from "./ec2";

const tags = (t?: { Key?: string; Value?: string }[]) => Object.fromEntries((t ?? []).map((x) => [x.Key!, x.Value ?? ""]));

export async function instances(): Promise<InventoryItem[]> {
  return (await listInstances())
    .filter((i) => i.State?.Name !== "terminated")
    .map((i) => ({
      service: "ec2",
      type: "Instance",
      id: i.InstanceId!,
      name: nameTag(i) ?? i.InstanceId!,
      href: LINKS.instance(i.InstanceId!),
      detail: `${i.InstanceType} · ${i.State?.Name}`,
      tags: tags(i.Tags),
    }));
}

/** Volumes; an unattached one costs money for nothing, so it is a signal. */
export async function volumes(): Promise<InventoryItem[]> {
  return (await listVolumes()).map((v) => ({
    service: "ec2",
    type: "EBS volume",
    id: v.VolumeId!,
    name: nameTag(v) ?? v.VolumeId!,
    href: LINKS.volume(v.VolumeId!),
    detail: `${v.Size} GiB ${v.VolumeType} · ${v.State}`,
    tags: tags(v.Tags),
    ...(v.State === "available" ? { signal: { tone: "warn" as const, text: "Not attached" } } : {}),
  }));
}

export async function templates(): Promise<InventoryItem[]> {
  return (await listTemplates()).map((t) => ({
    service: "ec2",
    type: "Launch template",
    id: t.LaunchTemplateId!,
    name: t.LaunchTemplateName!,
    href: LINKS.template(t.LaunchTemplateId!),
    detail: `v${t.DefaultVersionNumber}`,
    tags: tags(t.Tags),
  }));
}

export async function images(): Promise<InventoryItem[]> {
  return (await listImages(["self"])).map((i) => ({
    service: "ec2",
    type: "AMI",
    id: i.ImageId!,
    name: i.Name ?? i.ImageId!,
    href: LINKS.image(i.ImageId!),
    detail: `${i.Architecture} · ${i.State}`,
    tags: tags(i.Tags),
    ...(i.Public ? { signal: { tone: "warn" as const, text: "Public" } } : {}),
  }));
}

/** Security groups; one that opens admin or database ports to the internet is a signal. */
export async function securityGroups(): Promise<InventoryItem[]> {
  const [groups, rules] = await Promise.all([listGroups(), listRules()]);
  return groups.map((g) => {
    const exposed = rules.filter((r) => r.GroupId === g.GroupId && describeRule(r).exposed);
    return {
      service: "ec2",
      type: "Security group",
      id: g.GroupId!,
      name: g.GroupName!,
      href: LINKS.group(g.GroupId!),
      detail: g.VpcId,
      tags: tags(g.Tags),
      ...(exposed.length ? { signal: { tone: "bad" as const, text: `${describeRule(exposed[0]).ports} open to the internet` } } : {}),
    };
  });
}
