"use server";

import {
  AcceptResourceShareInvitationCommand,
  AssociateResourceShareCommand,
  AssociateResourceSharePermissionCommand,
  CreatePermissionCommand,
  CreatePermissionVersionCommand,
  CreateResourceShareCommand,
  DeletePermissionCommand,
  DeletePermissionVersionCommand,
  DeleteResourceShareCommand,
  DisassociateResourceShareCommand,
  DisassociateResourceSharePermissionCommand,
  EnableSharingWithAwsOrganizationCommand,
  RejectResourceShareInvitationCommand,
  ReplacePermissionAssociationsCommand,
  SetDefaultPermissionVersionCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateResourceShareCommand,
} from "@aws-sdk/client-ram";
import { act, FieldError, frameInfo, required, text, type ActionResult } from "@mws-dashboard/aws";
import { closest, type Repair } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { ram, shareTargets } from "../../lib/clients";

const lines = (s: string) => s.split(/[\s,]+/).filter(Boolean);

// RAM names the resource or principal it rejects; these put the problem on
// that item of its list field, in a few words. (Principals outside the
// organization stay under the form: the fix is the checkbox, not the item.)
const REJECTIONS: [RegExp, string, "missing" | "server"][] = [
  [/could not be found/, "Not found", "missing"],
  [/can't be shared with AWS RAM/, "Can't be shared with RAM", "server"],
  [/is not valid/, "Not a valid ARN", "server"],
  [/is malformed/, "Not an account, ARN or service", "server"],
  [/Your account doesn't own/, "Owned by another account", "server"],
  [/IAM roles and users only inside/, "Roles and users only inside your organization", "server"],
  [/sharing with AWS Organizations is not enabled/, "Organization sharing is off", "server"],
  [/only with your own organization/, "Not your organization", "server"],
  [/owner can't be a principal/, "That's your own account", "server"],
];

const short = (v: string) => (v.length > 32 ? `…${v.split(/[:/]/).pop()!.slice(-28)}` : v);

async function rejected(e: unknown, resources: string[], principals: string[]): Promise<FieldError | null> {
  if (!(e instanceof Error)) return null;
  const rule = REJECTIONS.find(([re]) => re.test(e.message));
  if (!rule) return null;
  const [, message, code] = rule;
  const own = /owner can't be a principal/.test(e.message) ? (await frameInfo()).account : null;
  const named = (v: string) => (own ? v === own : e.message.includes(v));
  // The longest match wins: an account ID is also part of its role ARNs.
  const hit = (list: string[]) => list.filter(named).sort((a, b) => b.length - a.length)[0];
  const organization = /Organizations is not enabled/.test(e.message) ? principals.find((p) => p.startsWith("arn:aws:organizations")) : undefined;
  const principal = hit(principals) ?? organization;
  const resource = hit(resources);
  const [field, value, list] = resource && (!principal || resource.length > principal.length) ? (["resources", resource, resources] as const) : principal ? (["principals", principal, principals] as const) : [];
  if (!field || !value || !list) return null;
  // The item it was probably meant to be, or the list without it.
  const targets = code === "missing" ? await shareTargets() : null;
  const at = (v: string | null) => list.flatMap((x) => (x === value ? (v === null ? [] : [v]) : [x])).join("\n");
  const repairs: Repair[] = closest(value, targets?.[field] ?? [], 2).map((v) => ({ value: at(v), label: `Did you mean ${short(v)}?`, kind: "suggest" }));
  if (list.length > 1) repairs.push({ value: at(null), label: `Remove ${short(value)}`, kind: "fix" });
  return new FieldError(field, `${short(value)}: ${message}`, code, undefined, repairs);
}

export async function createShare(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const resourceArns = lines(text(form, "resources"));
    const principals = lines(text(form, "principals"));
    const name = required(form, "name", "Name");
    const permissionArns = form.getAll("permission").filter((v): v is string => typeof v === "string" && !!v);
    const out = await (await ram())
      .send(new CreateResourceShareCommand({ name, resourceArns, principals, allowExternalPrincipals: text(form, "external") === "on", permissionArns: permissionArns.length ? permissionArns : undefined }))
      .catch(async (e: unknown) => {
        throw (await rejected(e, resourceArns, principals)) ?? e;
      });
    redirect(`/ram/share?arn=${encodeURIComponent(out.resourceShare!.resourceShareArn!)}`);
  });
}

export async function updateShare(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ram()).send(new UpdateResourceShareCommand({ resourceShareArn: arn, name: required(form, "name", "Name"), allowExternalPrincipals: text(form, "external") === "on" }));
    return "Share saved";
  }, { revalidate: ["/ram/share", "/ram"], fields: { name: "name" } });
}

/** Add resources and principals to a share. */
export async function associate(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const resourceArns = lines(text(form, "resources"));
    const principals = lines(text(form, "principals"));
    if (!resourceArns.length && !principals.length) throw new FieldError("resources", "Add a resource or a principal", "required");
    await (await ram())
      .send(new AssociateResourceShareCommand({ resourceShareArn: arn, resourceArns: resourceArns.length ? resourceArns : undefined, principals: principals.length ? principals : undefined }))
      .catch(async (e: unknown) => {
        throw (await rejected(e, resourceArns, principals)) ?? e;
      });
    return `Added ${resourceArns.length + principals.length}`;
  }, { revalidate: ["/ram/share"] });
}

export async function disassociate(arn: string, kind: "resource" | "principal", value: string) {
  return act(async () => {
    await (await ram()).send(new DisassociateResourceShareCommand({ resourceShareArn: arn, ...(kind === "resource" ? { resourceArns: [value] } : { principals: [value] }) }));
    return `Removed ${value.split(/[:/]/).pop()}`;
  }, "/ram/share");
}

export async function associatePermission(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const permissionArn = required(form, "permission", "Permission");
    await (await ram()).send(new AssociateResourceSharePermissionCommand({ resourceShareArn: arn, permissionArn, replace: form.get("replace") === "on" }));
    return "Permission associated";
  }, { revalidate: ["/ram/share"], fields: { permissionArn: "permission", InvalidParameterException: "permission", UnknownResourceException: "permission" } });
}

export async function disassociatePermission(arn: string, permissionArn: string) {
  return act(async () => {
    await (await ram()).send(new DisassociateResourceSharePermissionCommand({ resourceShareArn: arn, permissionArn }));
    return "Permission removed";
  }, "/ram/share");
}

export async function addShareTag(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const key = required(form, "key", "Key");
    await (await ram()).send(new TagResourceCommand({ resourceShareArn: arn, tags: [{ key, value: text(form, "value") }] }));
    return `Tagged ${key}`;
  }, { revalidate: ["/ram/share"], fields: { TagPolicyViolationException: "key", TagLimitExceededException: "key" } });
}

export async function removeShareTag(arn: string, key: string) {
  return act(async () => {
    await (await ram()).send(new UntagResourceCommand({ resourceShareArn: arn, tagKeys: [key] }));
    return `Removed ${key}`;
  }, "/ram/share");
}

export async function enableOrgSharing() {
  return act(async () => {
    const out = await (await ram()).send(new EnableSharingWithAwsOrganizationCommand({}));
    return out.returnValue ? "Sharing with your organization is on" : "Not enabled";
  }, "/ram");
}

// Customer managed permissions.

const permissionHref = (arn: string) => `/ram/permission?arn=${encodeURIComponent(arn)}`;

export async function createPermission(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ram()).send(
      new CreatePermissionCommand({ name: required(form, "name", "Name"), resourceType: required(form, "resourceType", "Resource type"), policyTemplate: required(form, "policy", "Policy template") }),
    );
    redirect(permissionHref(out.permission!.arn!));
  }, { fields: { name: "name", resourceType: "resourceType", policyTemplate: "policy", PermissionAlreadyExistsException: "name", MalformedPolicyTemplateException: "policy", InvalidPolicyException: "policy" } });
}

export async function createPermissionVersion(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ram()).send(new CreatePermissionVersionCommand({ permissionArn: arn, policyTemplate: required(form, "policy", "Policy template") }));
    return `Version ${out.permission?.version} created`;
  }, { revalidate: ["/ram/permission"], fields: { policyTemplate: "policy", MalformedPolicyTemplateException: "policy", InvalidPolicyException: "policy", PermissionVersionsLimitExceededException: "policy" } });
}

export async function setDefaultVersion(arn: string, version: number) {
  return act(async () => {
    await (await ram()).send(new SetDefaultPermissionVersionCommand({ permissionArn: arn, permissionVersion: version }));
    return `Version ${version} is the default`;
  }, "/ram/permission");
}

export async function deletePermissionVersion(arn: string, version: number) {
  return act(async () => {
    await (await ram()).send(new DeletePermissionVersionCommand({ permissionArn: arn, permissionVersion: version }));
    return `Version ${version} deleted`;
  }, "/ram/permission");
}

export async function deletePermission(arn: string) {
  return act(async () => {
    await (await ram()).send(new DeletePermissionCommand({ permissionArn: arn }));
    redirect("/ram?tab=permissions");
  });
}

/** Move every share using `from` (any version) onto the permission's default version. */
export async function replaceAssociations(arn: string, fromVersion: number) {
  return act(async () => {
    const out = await (await ram()).send(new ReplacePermissionAssociationsCommand({ fromPermissionArn: arn, fromPermissionVersion: fromVersion, toPermissionArn: arn }));
    return `Updating shares (${out.replacePermissionAssociationsWork?.status?.toLowerCase() ?? "started"})`;
  }, "/ram/permission");
}

export async function deleteShare(arn: string) {
  return act(async () => {
    await (await ram()).send(new DeleteResourceShareCommand({ resourceShareArn: arn }));
    redirect("/ram");
  });
}

export async function answerInvitation(arn: string, accept: boolean) {
  return act(async () => {
    const client = await ram();
    if (accept) await client.send(new AcceptResourceShareInvitationCommand({ resourceShareInvitationArn: arn }));
    else await client.send(new RejectResourceShareInvitationCommand({ resourceShareInvitationArn: arn }));
    return accept ? "Accepted" : "Rejected";
  }, "/ram");
}
