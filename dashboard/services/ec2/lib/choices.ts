import "server-only";

import { load } from "@mws-dashboard/aws";

import { nameTag } from "./clients";
import { launchableImages, listGroups, listInstanceProfiles, listKeyPairs, listSubnets, listTemplates, listVpcs } from "./ec2";
import type { LaunchChoices } from "./launch-fields";

const TYPES = ["t3.nano", "t3.micro", "t3.small", "t3.medium", "t3.large", "t4g.micro", "t4g.small", "m7i.large", "m7g.large", "c7g.large", "r7g.large"];

const value = <T,>(r: { ok: true; value: T } | { ok: false }, fallback: T) => (r.ok ? r.value : fallback);

/** What the launch and launch template forms offer. Each list loads on its
 * own, so a denied IAM listing still leaves the rest of the form. */
export async function launchChoices(): Promise<LaunchChoices> {
  const [images, keys, subnets, vpcs, groups, profiles, templates] = await Promise.all([
    load(launchableImages),
    load(listKeyPairs),
    load(listSubnets),
    load(listVpcs),
    load(() => listGroups()),
    load(listInstanceProfiles),
    load(listTemplates),
  ]);
  const vpcList = value(vpcs, []);
  const vpcLabel = (id: string) => {
    const v = vpcList.find((x) => x.VpcId === id);
    return `${(v && nameTag(v)) ?? id}${v?.IsDefault ? " (default)" : ""}`;
  };
  return {
    images: value(images, []).map((i) => ({
      id: i.ImageId!,
      name: i.Name,
      arch: i.Architecture,
      root: i.RootDeviceName,
      size: i.BlockDeviceMappings?.find((b) => b.DeviceName === i.RootDeviceName)?.Ebs?.VolumeSize,
    })),
    types: TYPES,
    keys: value(keys, []).map((k) => k.KeyName!),
    subnets: value(subnets, []).map((s) => ({
      id: s.SubnetId!,
      label: nameTag(s) ?? `${s.SubnetId} · ${s.CidrBlock}`,
      vpc: s.VpcId!,
      vpcLabel: vpcLabel(s.VpcId!),
      zone: s.AvailabilityZone ?? "",
      publicIp: !!s.MapPublicIpOnLaunch,
    })),
    groups: value(groups, []).map((g) => ({ id: g.GroupId!, name: g.GroupName!, vpc: g.VpcId ?? "" })),
    profiles: value(profiles, []).map((p) => ({ name: p.InstanceProfileName!, arn: p.Arn! })),
    templates: value(templates, []).map((t) => ({ id: t.LaunchTemplateId!, name: t.LaunchTemplateName!, latest: t.LatestVersionNumber ?? 1, default: t.DefaultVersionNumber ?? 1 })),
    defaultVpc: vpcList.find((v) => v.IsDefault)?.VpcId,
  };
}
