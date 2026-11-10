"use server";

import {
  AttachVolumeCommand,
  CopySnapshotCommand,
  CreateSnapshotCommand,
  CreateSnapshotsCommand,
  CreateVolumeCommand,
  DeleteSnapshotCommand,
  DeleteVolumeCommand,
  DetachVolumeCommand,
  ModifySnapshotAttributeCommand,
  ModifyVolumeCommand,
  type TagSpecification,
  type VolumeType,
} from "@aws-sdk/client-ec2";
import { act, FieldError, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ec2 } from "../../lib/clients";

const PATHS = ["/ec2", "/ec2/volume", "/ec2/instance"];

const named = (ResourceType: "volume" | "snapshot", name: string): TagSpecification[] | undefined =>
  name ? [{ ResourceType, Tags: [{ Key: "Name", Value: name }] }] : undefined;

const num = (form: FormData, field: string) => {
  const v = text(form, field);
  return v ? Number(v) : undefined;
};

const VOLUME_FIELDS = {
  Size: "size",
  VolumeType: "type",
  Iops: "iops",
  Throughput: "throughput",
  AvailabilityZone: "zone",
  SnapshotId: "snapshot",
  KmsKeyId: "kmsKey",
  "InvalidSnapshot.NotFound": "snapshot",
  InvalidZone: "zone",
  "InvalidZone.NotFound": "zone",
  InvalidParameterCombination: "iops",
};

export async function createVolume(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const type = (text(form, "type") || "gp3") as VolumeType;
    const snapshot = text(form, "snapshot");
    const out = await (await ec2()).send(
      new CreateVolumeCommand({
        AvailabilityZone: required(form, "zone", "Availability Zone"),
        Size: num(form, "size") ?? (snapshot ? undefined : 8),
        VolumeType: type,
        Iops: type === "gp3" || type === "io1" || type === "io2" ? num(form, "iops") : undefined,
        Throughput: type === "gp3" ? num(form, "throughput") : undefined,
        SnapshotId: snapshot || undefined,
        Encrypted: form.get("encrypted") === "on" || undefined,
        KmsKeyId: text(form, "kmsKey") || undefined,
        MultiAttachEnabled: form.get("multiAttach") === "on" || undefined,
        TagSpecifications: named("volume", text(form, "name")),
      }),
    );
    return `Created ${out.VolumeId}`;
  }, { revalidate: PATHS, fields: VOLUME_FIELDS });
}

export async function deleteVolume(id: string, back?: string) {
  const result = await act(async () => {
    await (await ec2()).send(new DeleteVolumeCommand({ VolumeId: id }));
    return `Deleting ${id}`;
  }, ...PATHS);
  if (result.ok && back) redirect(back);
  return result;
}

export async function attachVolume(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const instance = required(form, "instance", "Instance");
    const device = required(form, "device", "Device name");
    await (await ec2()).send(new AttachVolumeCommand({ VolumeId: id, InstanceId: instance, Device: device }));
    return `Attaching to ${instance}`;
  }, { revalidate: PATHS, fields: { InstanceId: "instance", Device: "device", "InvalidInstanceID.NotFound": "instance", IncorrectState: "instance", InvalidVolume: "instance", "InvalidParameterValue": "device", "InvalidVolume.ZoneMismatch": "instance" } });
}

export async function detachVolume(id: string, force: boolean) {
  return act(async () => {
    await (await ec2()).send(new DetachVolumeCommand({ VolumeId: id, Force: force || undefined }));
    return "Detaching";
  }, ...PATHS);
}

/** Grow a volume or change its type and performance: only what changed is sent. */
export async function modifyVolume(id: string, current: { size?: number; type?: string; iops?: number; throughput?: number }, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const type = text(form, "type") || current.type;
    const changed = <T,>(v: T | undefined, was: T | undefined) => (v !== undefined && v !== was ? v : undefined);
    const input = {
      VolumeId: id,
      Size: changed(num(form, "size"), current.size),
      VolumeType: changed(type, current.type) as VolumeType | undefined,
      Iops: type === "gp3" || type === "io1" || type === "io2" ? changed(num(form, "iops"), current.iops) : undefined,
      Throughput: type === "gp3" ? changed(num(form, "throughput"), current.throughput) : undefined,
    };
    if (input.Size === undefined && !input.VolumeType && input.Iops === undefined && input.Throughput === undefined) return "No changes";
    if (input.Size !== undefined && current.size && input.Size < current.size) throw new FieldError("size", "A volume can only grow", "range", { min: current.size });
    await (await ec2()).send(new ModifyVolumeCommand(input));
    return "Modifying";
  }, { revalidate: PATHS, fields: { ...VOLUME_FIELDS, IncorrectModificationState: "size", VolumeModificationRateExceeded: "size" } });
}

// ---------------------------------------------------------------------------
// Snapshots.

const SNAPSHOT_PATHS = ["/ec2", "/ec2/volume", "/ec2/instance"];

export async function createSnapshot(volumeId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ec2()).send(
      new CreateSnapshotCommand({ VolumeId: volumeId, Description: text(form, "description") || undefined, TagSpecifications: named("snapshot", text(form, "name")) }),
    );
    return `Creating ${out.SnapshotId}`;
  }, { revalidate: SNAPSHOT_PATHS, fields: { Description: "description" } });
}

/** One crash-consistent snapshot of each of an instance's volumes. */
export async function snapshotInstance(instanceId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ec2()).send(
      new CreateSnapshotsCommand({
        InstanceSpecification: { InstanceId: instanceId, ExcludeBootVolume: form.get("excludeRoot") === "on" || undefined },
        Description: text(form, "description") || undefined,
        CopyTagsFromSource: "volume",
      }),
    );
    return `Creating ${out.Snapshots?.length ?? 0} snapshots`;
  }, { revalidate: SNAPSHOT_PATHS, fields: { Description: "description" } });
}

export async function copySnapshot(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const destination = text(form, "region");
    const source = text(form, "sourceRegion") || (await region());
    const out = await (await ec2(destination || undefined)).send(
      new CopySnapshotCommand({
        SourceSnapshotId: id,
        SourceRegion: source,
        Description: text(form, "description") || undefined,
        Encrypted: form.get("encrypted") === "on" || undefined,
        KmsKeyId: text(form, "kmsKey") || undefined,
        TagSpecifications: named("snapshot", text(form, "name")),
      }),
    );
    return `Copying to ${out.SnapshotId}${destination && destination !== source ? ` in ${destination}` : ""}`;
  }, { revalidate: SNAPSHOT_PATHS, fields: { Description: "description", KmsKeyId: "kmsKey", DestinationRegion: "region" } });
}

export async function deleteSnapshot(id: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteSnapshotCommand({ SnapshotId: id }));
    return `Deleted ${id}`;
  }, ...SNAPSHOT_PATHS);
}

/** Share a snapshot with accounts, or stop sharing it. */
export async function shareSnapshot(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const account = required(form, "account", "Account ID");
    const remove = form.get("remove") === "on";
    await (await ec2()).send(
      new ModifySnapshotAttributeCommand({ SnapshotId: id, Attribute: "createVolumePermission", OperationType: remove ? "remove" : "add", UserIds: [account] }),
    );
    return remove ? `No longer shared with ${account}` : `Shared with ${account}`;
  }, { revalidate: SNAPSHOT_PATHS, fields: { UserIds: "account", UserId: "account" } });
}
