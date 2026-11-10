"use server";

import {
  CreateAccessPointCommand,
  CreateFileSystemCommand,
  CreateMountTargetCommand,
  CreateReplicationConfigurationCommand,
  DeleteAccessPointCommand,
  DeleteFileSystemCommand,
  DeleteFileSystemPolicyCommand,
  DeleteMountTargetCommand,
  DeleteReplicationConfigurationCommand,
  ModifyMountTargetSecurityGroupsCommand,
  PutBackupPolicyCommand,
  PutFileSystemPolicyCommand,
  PutLifecycleConfigurationCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateFileSystemCommand,
  UpdateFileSystemProtectionCommand,
  type LifecyclePolicy,
  type ThroughputMode,
  type TransitionToArchiveRules,
  type TransitionToIARules,
} from "@aws-sdk/client-efs";
import { act, describeError, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { efs, fsHref, mountTargets } from "../../lib/clients";
import { subnetsOf } from "../../lib/network";

const PAGES = ["/efs", "/efs/fs"];

const ids = (form: FormData, name: string) => form.getAll(name).map(String).filter(Boolean);

function lifecycleFrom(form: FormData): LifecyclePolicy[] {
  const ia = text(form, "ia");
  const archive = text(form, "archive");
  const back = text(form, "primary");
  return [
    ...(ia ? [{ TransitionToIA: ia as TransitionToIARules }] : []),
    ...(archive ? [{ TransitionToArchive: archive as TransitionToArchiveRules }] : []),
    ...(back ? [{ TransitionToPrimaryStorageClass: "AFTER_1_ACCESS" as const }] : []),
  ];
}

export async function createFileSystem(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = text(form, "name");
    const throughput = (text(form, "throughput") || "elastic") as ThroughputMode;
    const az = text(form, "az");
    const client = await efs();
    const out = await client.send(
      new CreateFileSystemCommand({
        CreationToken: `console-${Date.now()}`,
        PerformanceMode: (text(form, "performance") || "generalPurpose") as "generalPurpose" | "maxIO",
        ThroughputMode: throughput,
        ProvisionedThroughputInMibps: throughput === "provisioned" ? Number(required(form, "mibps", "Provisioned throughput")) : undefined,
        Encrypted: text(form, "encrypted") === "on",
        KmsKeyId: text(form, "encrypted") === "on" && text(form, "kms") ? text(form, "kms") : undefined,
        AvailabilityZoneName: az || undefined,
        Backup: text(form, "backup") === "on",
        Tags: name ? [{ Key: "Name", Value: name }] : undefined,
      }),
    );
    const id = out.FileSystemId!;
    const lifecycle = lifecycleFrom(form);
    const problems: string[] = [];
    if (lifecycle.length) await client.send(new PutLifecycleConfigurationCommand({ FileSystemId: id, LifecyclePolicies: lifecycle })).catch((e) => problems.push(`Lifecycle: ${describeError(e)}`));
    const vpc = text(form, "vpc");
    if (vpc) {
      // One mount target per Availability Zone, as the console's quick create
      // does (only the file system's zone for One Zone).
      const seen = new Set<string>();
      for (const s of await subnetsOf(vpc)) {
        if (seen.has(s.AvailabilityZone!) || (az && s.AvailabilityZone !== az)) continue;
        seen.add(s.AvailabilityZone!);
        try {
          await client.send(new CreateMountTargetCommand({ FileSystemId: id, SubnetId: s.SubnetId }));
        } catch (e) {
          problems.push(`Mount target in ${s.AvailabilityZone}: ${describeError(e)}`);
        }
      }
    }
    // The file system exists either way: show it, with what went wrong.
    redirect(`${fsHref(id)}${problems.length ? `&warn=${encodeURIComponent(problems.join("\n"))}` : ""}`);
  }, {
    fields: {
      "Tags.Value": "name",
      ThroughputMode: "throughput",
      ProvisionedThroughputInMibps: "mibps",
      PerformanceMode: "performance",
      KmsKeyId: "kms",
      AvailabilityZoneName: "az",
      UnsupportedAvailabilityZone: "az",
      SubnetId: "vpc",
      ThroughputLimitExceeded: "mibps",
      InsufficientThroughputCapacity: "mibps",
    },
  });
}

export async function deleteFileSystem(id: string) {
  return act(async () => {
    const client = await efs();
    for (const t of await mountTargets(id)) await client.send(new DeleteMountTargetCommand({ MountTargetId: t.MountTargetId }));
    await client.send(new DeleteFileSystemCommand({ FileSystemId: id }));
    redirect("/efs");
  }, { fields: { FileSystemInUse: "id" } });
}

export async function updateFileSystem(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const mode = (text(form, "throughput") || "elastic") as ThroughputMode;
    await (await efs()).send(
      new UpdateFileSystemCommand({ FileSystemId: id, ThroughputMode: mode, ProvisionedThroughputInMibps: mode === "provisioned" ? Number(required(form, "mibps", "Provisioned throughput")) : undefined }),
    );
    return "Throughput updated";
  }, { revalidate: PAGES, fields: { ThroughputMode: "throughput", ProvisionedThroughputInMibps: "mibps", TooManyRequests: "throughput", ThroughputLimitExceeded: "mibps", InsufficientThroughputCapacity: "mibps" } });
}

export async function saveLifecycle(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await efs()).send(new PutLifecycleConfigurationCommand({ FileSystemId: id, LifecyclePolicies: lifecycleFrom(form) }));
    return "Lifecycle management saved";
  }, { revalidate: PAGES, fields: { LifecyclePolicies: "ia" } });
}

export async function setBackup(id: string, on: boolean) {
  return act(async () => {
    await (await efs()).send(new PutBackupPolicyCommand({ FileSystemId: id, BackupPolicy: { Status: on ? "ENABLED" : "DISABLED" } }));
    return on ? "Automatic backups on" : "Automatic backups off";
  }, ...PAGES);
}

export async function setProtection(id: string, on: boolean) {
  return act(async () => {
    await (await efs()).send(new UpdateFileSystemProtectionCommand({ FileSystemId: id, ReplicationOverwriteProtection: on ? "ENABLED" : "DISABLED" }));
    return on ? "Replication overwrite protection on" : "Replication overwrite protection off";
  }, ...PAGES);
}

export async function savePolicy(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = text(form, "policy");
    const client = await efs();
    if (!policy) {
      await client.send(new DeleteFileSystemPolicyCommand({ FileSystemId: id }));
      return "Policy removed";
    }
    try {
      JSON.parse(policy);
    } catch {
      throw new FieldError("policy", "Invalid JSON", "format");
    }
    await client.send(new PutFileSystemPolicyCommand({ FileSystemId: id, Policy: policy, BypassPolicyLockoutSafetyCheck: text(form, "bypass") === "on" }));
    return "Policy saved";
  }, { revalidate: PAGES, fields: { Policy: "policy", InvalidPolicyException: "policy" } });
}

export async function createMountTarget(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const groups = ids(form, "groups");
    await (await efs()).send(
      new CreateMountTargetCommand({ FileSystemId: id, SubnetId: required(form, "subnet", "Subnet"), IpAddress: text(form, "ip") || undefined, SecurityGroups: groups.length ? groups : undefined }),
    );
    return "Mount target created";
  }, {
    revalidate: PAGES,
    fields: {
      SubnetId: "subnet",
      SubnetNotFound: "subnet",
      MountTargetConflict: "subnet",
      AvailabilityZonesMismatch: "subnet",
      NoFreeAddressesInSubnet: "subnet",
      IpAddress: "ip",
      IpAddressInUse: "ip",
      SecurityGroups: "groups",
      SecurityGroupNotFound: "groups",
      SecurityGroupLimitExceeded: "groups",
    },
  });
}

export async function deleteMountTarget(target: string) {
  return act(async () => {
    await (await efs()).send(new DeleteMountTargetCommand({ MountTargetId: target }));
    return "Mount target deleted";
  }, ...PAGES);
}

export async function saveSecurityGroups(target: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const groups = ids(form, "groups");
    if (!groups.length) throw new FieldError("groups", "Choose at least one security group", "required");
    await (await efs()).send(new ModifyMountTargetSecurityGroupsCommand({ MountTargetId: target, SecurityGroups: groups }));
    return "Security groups saved";
  }, { revalidate: PAGES, fields: { SecurityGroups: "groups", SecurityGroupNotFound: "groups", SecurityGroupLimitExceeded: "groups", IncorrectMountTargetState: "groups" } });
}

export async function createAccessPoint(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const uid = Number(text(form, "uid") || 1000);
    const gid = Number(text(form, "gid") || uid);
    const secondary = text(form, "secondary")
      .split(/[\s,]+/)
      .filter(Boolean)
      .map(Number);
    const path = required(form, "path", "Root directory");
    const create = path !== "/";
    await (await efs()).send(
      new CreateAccessPointCommand({
        FileSystemId: id,
        ClientToken: `console-${Date.now()}`,
        PosixUser: { Uid: uid, Gid: gid, SecondaryGids: secondary.length ? secondary : undefined },
        RootDirectory: {
          Path: path,
          CreationInfo: create
            ? { OwnerUid: Number(text(form, "ownerUid") || uid), OwnerGid: Number(text(form, "ownerGid") || gid), Permissions: text(form, "permissions") || "755" }
            : undefined,
        },
        Tags: text(form, "name") ? [{ Key: "Name", Value: text(form, "name") }] : undefined,
      }),
    );
    return "Access point created";
  }, {
    revalidate: PAGES,
    fields: {
      "Tags.Value": "name",
      "RootDirectory.Path": "path",
      "PosixUser.Uid": "uid",
      "PosixUser.Gid": "gid",
      "PosixUser.SecondaryGids": "secondary",
      "RootDirectory.CreationInfo.OwnerUid": "ownerUid",
      "RootDirectory.CreationInfo.OwnerGid": "ownerGid",
      "RootDirectory.CreationInfo.Permissions": "permissions",
    },
  });
}

export async function deleteAccessPoint(id: string) {
  return act(async () => {
    await (await efs()).send(new DeleteAccessPointCommand({ AccessPointId: id }));
    return "Access point deleted";
  }, ...PAGES);
}

export async function createReplication(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const existing = text(form, "destination");
    const Region = required(form, "region", "Destination Region");
    await (await efs()).send(
      new CreateReplicationConfigurationCommand({
        SourceFileSystemId: id,
        Destinations: [{ Region, FileSystemId: existing || undefined, AvailabilityZoneName: text(form, "az") || undefined, KmsKeyId: text(form, "kms") || undefined }],
      }),
    );
    return "Replication created";
  }, {
    revalidate: PAGES,
    fields: { "Destinations.Region": "region", Region: "region", "Destinations.FileSystemId": "destination", FileSystemNotFound: "destination", ReplicationAlreadyExists: "destination", "Destinations.KmsKeyId": "kms", "Destinations.AvailabilityZoneName": "az" },
  });
}

export async function deleteReplication(id: string) {
  return act(async () => {
    await (await efs()).send(new DeleteReplicationConfigurationCommand({ SourceFileSystemId: id }));
    return "Replication deleted";
  }, ...PAGES);
}

export async function saveTags(resource: string, current: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const tags = text(form, "tags")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [Key, ...rest] = l.split("=");
        return { Key: Key.trim(), Value: rest.join("=").trim() };
      });
    const client = await efs();
    const gone = current.filter((k) => !tags.some((t) => t.Key === k));
    if (gone.length) await client.send(new UntagResourceCommand({ ResourceId: resource, TagKeys: gone }));
    if (tags.length) await client.send(new TagResourceCommand({ ResourceId: resource, Tags: tags }));
    return "Tags saved";
  }, { revalidate: PAGES, fields: { Tags: "tags", "Tags.Key": "tags", "Tags.Value": "tags" } });
}
