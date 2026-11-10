"use server";

import {
  CreateGroupCommand,
  CreateGroupMembershipCommand,
  CreateUserCommand,
  DeleteGroupCommand,
  DeleteGroupMembershipCommand,
  DeleteUserCommand,
  UpdateGroupCommand,
  UpdateUserCommand,
  type AttributeOperation,
} from "@aws-sdk/client-identitystore";
import {
  AttachCustomerManagedPolicyReferenceToPermissionSetCommand,
  AttachManagedPolicyToPermissionSetCommand,
  CreateAccountAssignmentCommand,
  CreateInstanceCommand,
  CreatePermissionSetCommand,
  DeleteAccountAssignmentCommand,
  DeleteInlinePolicyFromPermissionSetCommand,
  DeletePermissionSetCommand,
  DeletePermissionsBoundaryFromPermissionSetCommand,
  DetachCustomerManagedPolicyReferenceFromPermissionSetCommand,
  DetachManagedPolicyFromPermissionSetCommand,
  ProvisionPermissionSetCommand,
  PutInlinePolicyToPermissionSetCommand,
  PutPermissionsBoundaryToPermissionSetCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateInstanceCommand,
  UpdatePermissionSetCommand,
  type PrincipalType,
} from "@aws-sdk/client-sso-admin";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { identitystore, ssoAdmin } from "../../lib/clients";
import { assignmentsForPrincipal } from "../../lib/sso";

const ROOT = "/identitycenter";
const setPage = (set: string) => `${ROOT}/permissionset?arn=${encodeURIComponent(set)}`;

const hours = (form: FormData, field = "hours") => {
  const n = Number(text(form, field) || 1);
  if (!Number.isFinite(n) || n < 1 || n > 12) throw new FieldError(field, "Between 1 and 12 hours", "range", { type: "number", min: 1, max: 12 });
  const h = Math.floor(n);
  const m = Math.round((n - h) * 60);
  return `PT${h}H${m ? `${m}M` : ""}`;
};

function policyJson(form: FormData, field: string) {
  const value = required(form, field, "Policy");
  try {
    JSON.parse(value);
  } catch {
    throw new FieldError(field, "Invalid JSON", "format");
  }
  return value;
}

export async function enableInstance() {
  return act(async () => {
    await (await ssoAdmin()).send(new CreateInstanceCommand({ Name: "default" }));
    return "Identity Center enabled";
  }, ROOT);
}

export async function updateInstance(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ssoAdmin()).send(new UpdateInstanceCommand({ InstanceArn: arn, Name: required(form, "name", "Name") }));
    return "Saved";
  }, { revalidate: [`${ROOT}/settings`], fields: { Name: "name" } });
}

/** An account instance starts with permission sets off; turning them on is one-way. */
export async function enablePermissionSets(arn: string) {
  return act(async () => {
    await (await ssoAdmin()).send(new UpdateInstanceCommand({ InstanceArn: arn, PermissionSetsEnabled: true }));
    return "Permission sets enabled";
  }, ROOT, `${ROOT}/settings`);
}

export async function createUser(store: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const UserName = required(form, "username", "Username");
    const given = required(form, "given", "First name");
    const family = required(form, "family", "Last name");
    await (await identitystore()).send(
      new CreateUserCommand({
        IdentityStoreId: store,
        UserName,
        DisplayName: text(form, "display") || `${given} ${family}`,
        Name: { GivenName: given, FamilyName: family },
        Emails: text(form, "email") ? [{ Value: text(form, "email"), Primary: true, Type: "work" }] : undefined,
      }),
    );
    return `Added ${UserName}`;
  }, { revalidate: [ROOT], fields: { UserName: "username", DisplayName: "display", "Name.GivenName": "given", "Name.FamilyName": "family", "Emails.Value": "email" } });
}

/** Changed attributes only, as UpdateUser operations (an empty value removes it). */
export async function updateUser(store: string, id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Operations: AttributeOperation[] = [
      { AttributePath: "displayName", AttributeValue: required(form, "display", "Display name") },
      { AttributePath: "name.givenName", AttributeValue: required(form, "given", "First name") },
      { AttributePath: "name.familyName", AttributeValue: required(form, "family", "Last name") },
      { AttributePath: "title", AttributeValue: text(form, "title") || undefined },
      { AttributePath: "emails", AttributeValue: text(form, "email") ? [{ value: text(form, "email"), type: "work", primary: true }] : undefined },
      { AttributePath: "phoneNumbers", AttributeValue: text(form, "phone") ? [{ value: text(form, "phone"), type: "work", primary: true }] : undefined },
    ];
    await (await identitystore()).send(new UpdateUserCommand({ IdentityStoreId: store, UserId: id, Operations }));
    return "User saved";
  }, { revalidate: [`${ROOT}/users/${id}`], fields: { displayName: "display", "name.givenName": "given", "name.familyName": "family", emails: "email", phoneNumbers: "phone", title: "title" } });
}

/** Remove a principal's account assignments, as AWS's console does before
 * deleting a user or group. */
async function unassign(instance: string | undefined, id: string, type: PrincipalType) {
  if (!instance) return;
  const admin = await ssoAdmin();
  for (const a of await assignmentsForPrincipal(instance, id, type)) {
    await admin.send(
      new DeleteAccountAssignmentCommand({ InstanceArn: instance, TargetId: a.AccountId, TargetType: "AWS_ACCOUNT", PermissionSetArn: a.PermissionSetArn, PrincipalId: id, PrincipalType: type }),
    );
  }
}

export async function deleteUser(store: string, id: string, instance?: string, back?: boolean) {
  return act(async () => {
    await unassign(instance, id, "USER");
    await (await identitystore()).send(new DeleteUserCommand({ IdentityStoreId: store, UserId: id }));
    if (back) redirect(ROOT);
    return "User deleted";
  }, ROOT);
}

export async function createGroup(store: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const DisplayName = required(form, "name", "Group name");
    await (await identitystore()).send(new CreateGroupCommand({ IdentityStoreId: store, DisplayName, Description: text(form, "description") || undefined }));
    return `Created ${DisplayName}`;
  }, { revalidate: [ROOT], fields: { DisplayName: "name", Description: "description" } });
}

export async function updateGroup(store: string, id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await identitystore()).send(
      new UpdateGroupCommand({
        IdentityStoreId: store,
        GroupId: id,
        Operations: [
          { AttributePath: "displayName", AttributeValue: required(form, "name", "Group name") },
          { AttributePath: "description", AttributeValue: text(form, "description") || undefined },
        ],
      }),
    );
    return "Group saved";
  }, { revalidate: [`${ROOT}/groups/${id}`], fields: { displayName: "name", description: "description", ConflictException: "name" } });
}

export async function deleteGroup(store: string, id: string, instance?: string, back?: boolean) {
  return act(async () => {
    await unassign(instance, id, "GROUP");
    await (await identitystore()).send(new DeleteGroupCommand({ IdentityStoreId: store, GroupId: id }));
    if (back) redirect(`${ROOT}?tab=groups`);
    return "Group deleted";
  }, ROOT);
}

/** Add a user to a group, from either side: the form names the other one. */
export async function addMembership(store: string, fixed: { group?: string; user?: string }, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const GroupId = fixed.group ?? required(form, "group", "Group");
    const UserId = fixed.user ?? required(form, "user", "User");
    await (await identitystore()).send(new CreateGroupMembershipCommand({ IdentityStoreId: store, GroupId, MemberId: { UserId } }));
    return "Added";
  }, { revalidate: [`${ROOT}/groups/${fixed.group ?? text(form, "group")}`, `${ROOT}/users/${fixed.user ?? text(form, "user")}`], fields: { GroupId: "group", MemberId: "user", "MemberId.UserId": "user", ConflictException: fixed.group ? "user" : "group" } });
}

export async function deleteMembership(store: string, membership: string, group: string, user: string) {
  return act(async () => {
    await (await identitystore()).send(new DeleteGroupMembershipCommand({ IdentityStoreId: store, MembershipId: membership }));
    return "Removed";
  }, `${ROOT}/groups/${group}`, `${ROOT}/users/${user}`);
}

export async function createPermissionSet(instance: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Name");
    const client = await ssoAdmin();
    const out = await client.send(
      new CreatePermissionSetCommand({ InstanceArn: instance, Name, SessionDuration: hours(form), Description: text(form, "description") || undefined, RelayState: text(form, "relay") || undefined }),
    );
    const policy = text(form, "policy");
    if (policy) await client.send(new AttachManagedPolicyToPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: out.PermissionSet!.PermissionSetArn, ManagedPolicyArn: policy }));
    return `Created ${Name}`;
  }, { revalidate: [ROOT], fields: { Name: "name", Description: "description", SessionDuration: "hours", RelayState: "relay", ManagedPolicyArn: "policy" } });
}

export async function updatePermissionSet(instance: string, set: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ssoAdmin()).send(
      new UpdatePermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set, Description: text(form, "description") || undefined, SessionDuration: hours(form), RelayState: text(form, "relay") || undefined }),
    );
    return "Saved: provision it to update the accounts";
  }, { revalidate: [setPage(set)], fields: { Description: "description", SessionDuration: "hours", RelayState: "relay" } });
}

export async function deletePermissionSet(instance: string, arn: string, back?: boolean) {
  return act(async () => {
    await (await ssoAdmin()).send(new DeletePermissionSetCommand({ InstanceArn: instance, PermissionSetArn: arn }));
    if (back) redirect(`${ROOT}?tab=permissionsets`);
    return "Permission set deleted";
  }, ROOT);
}

export async function attachManagedPolicy(instance: string, set: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const ManagedPolicyArn = required(form, "policy", "Policy");
    await (await ssoAdmin()).send(new AttachManagedPolicyToPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set, ManagedPolicyArn }));
    return `Attached ${ManagedPolicyArn.split("/").pop()}`;
  }, { revalidate: [setPage(set)], fields: { ManagedPolicyArn: "policy", ConflictException: "policy", ResourceNotFoundException: "policy", ServiceQuotaExceededException: "policy" } });
}

export async function detachManagedPolicy(instance: string, set: string, policy: string) {
  return act(async () => {
    await (await ssoAdmin()).send(new DetachManagedPolicyFromPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set, ManagedPolicyArn: policy }));
    return "Detached";
  }, setPage(set));
}

export async function attachCustomerPolicy(instance: string, set: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Policy name");
    await (await ssoAdmin()).send(
      new AttachCustomerManagedPolicyReferenceToPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set, CustomerManagedPolicyReference: { Name, Path: text(form, "path") || undefined } }),
    );
    return `Attached ${Name}`;
  }, { revalidate: [setPage(set)], fields: { "CustomerManagedPolicyReference.Name": "name", "CustomerManagedPolicyReference.Path": "path", ConflictException: "name", ServiceQuotaExceededException: "name" } });
}

export async function detachCustomerPolicy(instance: string, set: string, name: string, path: string | undefined) {
  return act(async () => {
    await (await ssoAdmin()).send(
      new DetachCustomerManagedPolicyReferenceFromPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set, CustomerManagedPolicyReference: { Name: name, Path: path } }),
    );
    return "Detached";
  }, setPage(set));
}

export async function putInlinePolicy(instance: string, set: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ssoAdmin()).send(new PutInlinePolicyToPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set, InlinePolicy: policyJson(form, "document") }));
    return "Inline policy saved";
  }, { revalidate: [setPage(set)], fields: { InlinePolicy: "document", ValidationException: "document" } });
}

export async function deleteInlinePolicy(instance: string, set: string) {
  return act(async () => {
    await (await ssoAdmin()).send(new DeleteInlinePolicyFromPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set }));
    return "Inline policy removed";
  }, setPage(set));
}

/** A boundary is an AWS managed policy ARN or a customer managed policy name (path optional). */
export async function putBoundary(instance: string, set: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = required(form, "policy", "Policy");
    const PermissionsBoundary = policy.startsWith("arn:")
      ? { ManagedPolicyArn: policy }
      : { CustomerManagedPolicyReference: { Name: policy.split("/").pop()!, Path: policy.includes("/") ? policy.slice(0, policy.lastIndexOf("/") + 1).replace(/^(?!\/)/, "/") : undefined } };
    await (await ssoAdmin()).send(new PutPermissionsBoundaryToPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set, PermissionsBoundary }));
    return "Boundary set";
  }, { revalidate: [setPage(set)], fields: { PermissionsBoundary: "policy", "PermissionsBoundary.ManagedPolicyArn": "policy", "PermissionsBoundary.CustomerManagedPolicyReference.Name": "policy" } });
}

export async function deleteBoundary(instance: string, set: string) {
  return act(async () => {
    await (await ssoAdmin()).send(new DeletePermissionsBoundaryFromPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set }));
    return "Boundary removed";
  }, setPage(set));
}

/** Push the permission set to every account it is assigned in. */
export async function provisionPermissionSet(instance: string, set: string) {
  return act(async () => {
    const out = await (await ssoAdmin()).send(new ProvisionPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: set, TargetType: "ALL_PROVISIONED_ACCOUNTS" }));
    const s = out.PermissionSetProvisioningStatus;
    if (s?.Status === "FAILED") throw new Error(s.FailureReason ?? "Provisioning failed");
    return `Provisioning ${s?.Status === "SUCCEEDED" ? "done" : "started"}`;
  }, ROOT, setPage(set));
}

export async function savePermissionSetTags(instance: string, set: string, current: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Tags = text(form, "tags")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l, i) => {
        const [Key, ...rest] = l.split("=");
        if (!rest.length || !Key.trim()) throw new FieldError("tags", `Line ${i + 1}: key=value`, "format");
        return { Key: Key.trim(), Value: rest.join("=").trim() };
      });
    const client = await ssoAdmin();
    const TagKeys = current.filter((k) => !Tags.some((t) => t.Key === k));
    if (TagKeys.length) await client.send(new UntagResourceCommand({ InstanceArn: instance, ResourceArn: set, TagKeys }));
    if (Tags.length) await client.send(new TagResourceCommand({ InstanceArn: instance, ResourceArn: set, Tags }));
    return "Tags saved";
  }, { revalidate: [setPage(set)], fields: { Tags: "tags", TagKeys: "tags" } });
}

/** Give a user or group a permission set in an account. Any of the three
 * may be fixed by the page (an account's, a user's, a group's). The call
 * answers IN_PROGRESS; the page follows the status. */
export async function createAssignment(
  instance: string,
  fixed: { account?: string; principal?: string; set?: string },
  _: ActionResult | null,
  form: FormData,
) {
  return act(async () => {
    const TargetId = fixed.account ?? required(form, "account", "Account");
    const [type, PrincipalId] = (fixed.principal ?? required(form, "principal", "User or group")).split(":");
    const PermissionSetArn = fixed.set ?? required(form, "set", "Permission set");
    const out = await (await ssoAdmin()).send(
      new CreateAccountAssignmentCommand({ InstanceArn: instance, TargetId, TargetType: "AWS_ACCOUNT", PermissionSetArn, PrincipalType: type as PrincipalType, PrincipalId }),
    );
    const s = out.AccountAssignmentCreationStatus;
    if (s?.Status === "FAILED") throw new Error(s.FailureReason ?? "Assignment failed");
    return s?.Status === "SUCCEEDED" ? "Assigned" : "Assigning";
  }, { revalidate: [ROOT, `${ROOT}/accounts/${fixed.account ?? text(form, "account")}`], fields: { TargetId: "account", PrincipalId: "principal", PermissionSetArn: "set", ConflictException: "set" } });
}

export async function deleteAssignment(instance: string, account: string, set: string, type: PrincipalType, principal: string) {
  return act(async () => {
    const out = await (await ssoAdmin()).send(
      new DeleteAccountAssignmentCommand({ InstanceArn: instance, TargetId: account, TargetType: "AWS_ACCOUNT", PermissionSetArn: set, PrincipalType: type, PrincipalId: principal }),
    );
    const s = out.AccountAssignmentDeletionStatus;
    if (s?.Status === "FAILED") throw new Error(s.FailureReason ?? "Removal failed");
    return "Assignment removed";
  }, ROOT, `${ROOT}/accounts/${account}`, `${ROOT}/${type === "USER" ? "users" : "groups"}/${principal}`);
}
