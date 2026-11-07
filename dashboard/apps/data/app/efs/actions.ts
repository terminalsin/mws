"use server";

import { DescribeSubnetsCommand } from "@aws-sdk/client-ec2";
import { CreateAccessPointCommand, CreateFileSystemCommand, CreateMountTargetCommand, DeleteAccessPointCommand, DeleteFileSystemCommand, DeleteMountTargetCommand } from "@aws-sdk/client-efs";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ec2, efs } from "../../lib/clients";
import { subnetsOf } from "../../lib/eks";

export async function createFileSystem(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = text(form, "name");
    const out = await (await efs()).send(
      new CreateFileSystemCommand({
        CreationToken: `console-${Date.now()}`,
        PerformanceMode: (text(form, "performance") || "generalPurpose") as "generalPurpose" | "maxIO",
        ThroughputMode: (text(form, "throughput") || "elastic") as "elastic" | "bursting",
        Encrypted: text(form, "encrypted") === "on",
        Tags: name ? [{ Key: "Name", Value: name }] : undefined,
      }),
    );
    const vpc = text(form, "vpc");
    if (vpc) {
      // One mount target per Availability Zone, as the console's quick create does.
      const client = await efs();
      const seen = new Set<string>();
      const subnets = (await (await ec2()).send(new DescribeSubnetsCommand({ SubnetIds: await subnetsOf(vpc) }))).Subnets ?? [];
      for (const s of subnets) {
        if (seen.has(s.AvailabilityZone!)) continue;
        seen.add(s.AvailabilityZone!);
        await client.send(new CreateMountTargetCommand({ FileSystemId: out.FileSystemId, SubnetId: s.SubnetId }));
      }
    }
    redirect(`/efs/fs?id=${out.FileSystemId}`);
  });
}

export async function deleteFileSystem(id: string, targets: string[]) {
  return act(async () => {
    const client = await efs();
    for (const t of targets) await client.send(new DeleteMountTargetCommand({ MountTargetId: t }));
    await client.send(new DeleteFileSystemCommand({ FileSystemId: id }));
    redirect("/efs");
  });
}

export async function createAccessPoint(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const uid = Number(text(form, "uid") || 1000);
    await (await efs()).send(
      new CreateAccessPointCommand({
        FileSystemId: id,
        ClientToken: `console-${Date.now()}`,
        PosixUser: { Uid: uid, Gid: uid },
        RootDirectory: { Path: required(form, "path", "Root directory"), CreationInfo: { OwnerUid: uid, OwnerGid: uid, Permissions: "755" } },
        Tags: text(form, "name") ? [{ Key: "Name", Value: text(form, "name") }] : undefined,
      }),
    );
    return "Access point created";
  }, "/efs/fs");
}

export async function deleteAccessPoint(id: string) {
  return act(async () => {
    await (await efs()).send(new DeleteAccessPointCommand({ AccessPointId: id }));
    return "Access point deleted";
  }, "/efs/fs");
}
