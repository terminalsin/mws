"use server";

import {
  CopyImageCommand,
  CreateImageCommand,
  DeregisterImageCommand,
  DisableImageCommand,
  DisableImageDeprecationCommand,
  DisableImageDeregistrationProtectionCommand,
  EnableImageCommand,
  EnableImageDeprecationCommand,
  EnableImageDeregistrationProtectionCommand,
  ModifyImageAttributeCommand,
} from "@aws-sdk/client-ec2";
import { act, FieldError, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ec2 } from "../../lib/clients";

const PATHS = ["/ec2", "/ec2/image", "/ec2/instance"];
const NAME_FIELDS = { Name: "name", Description: "description", "InvalidAMIName.Duplicate": "name", "InvalidAMIName.Malformed": "name" };

/** An AMI of a stopped or running instance (and snapshots of its volumes). */
export async function createImage(instanceId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Image name");
    const out = await (await ec2())
      .send(
        new CreateImageCommand({
          InstanceId: instanceId,
          Name: name,
          Description: text(form, "description") || undefined,
          NoReboot: form.get("noReboot") === "on" || undefined,
          TagSpecifications: [{ ResourceType: "image", Tags: [{ Key: "Name", Value: name }] }],
        }),
      )
      .catch((e: Error) => {
        if (e.name === "InvalidAMIName.Duplicate") throw new FieldError("name", "An image already has this name", "taken");
        throw e;
      });
    return { ok: true, message: `Creating ${out.ImageId}`, detail: out.ImageId };
  }, { revalidate: PATHS, fields: NAME_FIELDS });
}

export async function copyImage(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const source = await region();
    const destination = text(form, "region") || source;
    const out = await (await ec2(destination)).send(
      new CopyImageCommand({
        SourceImageId: id,
        SourceRegion: source,
        Name: required(form, "name", "Name"),
        Description: text(form, "description") || undefined,
        Encrypted: form.get("encrypted") === "on" || undefined,
        CopyImageTags: form.get("copyTags") === "on" || undefined,
      }),
    );
    return `Copying to ${out.ImageId}${destination !== source ? ` in ${destination}` : ""}`;
  }, { revalidate: PATHS, fields: NAME_FIELDS });
}

export async function deregisterImage(id: string, deleteSnapshots: boolean) {
  const result = await act(async () => {
    await (await ec2()).send(new DeregisterImageCommand({ ImageId: id, DeleteAssociatedSnapshots: deleteSnapshots || undefined }));
    return `Deregistered ${id}`;
  }, ...PATHS);
  if (result.ok) redirect("/ec2?tab=images");
  return result;
}

export async function setDescription(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ec2()).send(new ModifyImageAttributeCommand({ ImageId: id, Description: { Value: text(form, "description") } }));
    return "Saved";
  }, { revalidate: PATHS, fields: { Description: "description" } });
}

/** Launch permissions: public, or specific accounts. */
export async function shareImage(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const account = text(form, "account");
    const remove = form.get("remove") === "on";
    if (!account) throw new FieldError("account", "Account ID is required", "required");
    const entry = account === "all" ? { Group: "all" as const } : { UserId: account };
    await (await ec2()).send(
      new ModifyImageAttributeCommand({ ImageId: id, Attribute: "launchPermission", LaunchPermission: remove ? { Remove: [entry] } : { Add: [entry] } }),
    );
    return remove ? "Permission removed" : account === "all" ? "Now public" : `Shared with ${account}`;
  }, { revalidate: PATHS, fields: { UserId: "account", InvalidAMIAttributeItemValue: "account" } });
}

export async function unshareImage(id: string, account: string) {
  return act(async () => {
    const entry = account === "all" ? { Group: "all" as const } : { UserId: account };
    await (await ec2()).send(new ModifyImageAttributeCommand({ ImageId: id, Attribute: "launchPermission", LaunchPermission: { Remove: [entry] } }));
    return account === "all" ? "No longer public" : `No longer shared with ${account}`;
  }, ...PATHS);
}

export async function deprecateImage(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const at = required(form, "at", "Deprecation date");
    // datetime-local has no zone: the field says UTC.
    const date = new Date(/T\d\d:\d\d$/.test(at) ? `${at}:00Z` : at);
    if (Number.isNaN(date.getTime())) throw new FieldError("at", "Not a date", "format");
    await (await ec2()).send(new EnableImageDeprecationCommand({ ImageId: id, DeprecateAt: date }));
    return `Deprecates ${date.toISOString().slice(0, 16).replace("T", " ")}`;
  }, { revalidate: PATHS, fields: { DeprecateAt: "at", InvalidParameterValue: "at" } });
}

export async function undeprecateImage(id: string) {
  return act(async () => {
    await (await ec2()).send(new DisableImageDeprecationCommand({ ImageId: id }));
    return "Deprecation cancelled";
  }, ...PATHS);
}

export async function protectImage(id: string, on: boolean) {
  return act(async () => {
    const client = await ec2();
    if (on) await client.send(new EnableImageDeregistrationProtectionCommand({ ImageId: id, WithCooldown: false }));
    else await client.send(new DisableImageDeregistrationProtectionCommand({ ImageId: id }));
    return on ? "Deregistration protection on" : "Deregistration protection off";
  }, ...PATHS);
}

export async function enableImage(id: string, on: boolean) {
  return act(async () => {
    const client = await ec2();
    if (on) await client.send(new EnableImageCommand({ ImageId: id }));
    else await client.send(new DisableImageCommand({ ImageId: id }));
    return on ? "Enabled" : "Disabled";
  }, ...PATHS);
}
