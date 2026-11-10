"use server";

import {
  AddRoleToInstanceProfileCommand,
  AddUserToGroupCommand,
  AttachGroupPolicyCommand,
  AttachRolePolicyCommand,
  AttachUserPolicyCommand,
  CreateAccessKeyCommand,
  CreateAccountAliasCommand,
  CreateGroupCommand,
  CreateInstanceProfileCommand,
  CreateLoginProfileCommand,
  CreateOpenIDConnectProviderCommand,
  CreateSAMLProviderCommand,
  CreatePolicyCommand,
  CreatePolicyVersionCommand,
  CreateRoleCommand,
  CreateUserCommand,
  DeactivateMFADeviceCommand,
  DeleteAccessKeyCommand,
  DeleteAccountAliasCommand,
  DeleteAccountPasswordPolicyCommand,
  DeleteGroupCommand,
  DeleteGroupPolicyCommand,
  DeleteInstanceProfileCommand,
  DeleteLoginProfileCommand,
  DeleteOpenIDConnectProviderCommand,
  DeletePolicyCommand,
  DeletePolicyVersionCommand,
  DeleteRoleCommand,
  DeleteRolePermissionsBoundaryCommand,
  DeleteRolePolicyCommand,
  DeleteSAMLProviderCommand,
  DeleteServiceLinkedRoleCommand,
  DeleteServiceSpecificCredentialCommand,
  DeleteSigningCertificateCommand,
  DeleteSSHPublicKeyCommand,
  DeleteUserCommand,
  DeleteUserPermissionsBoundaryCommand,
  DeleteUserPolicyCommand,
  DeleteVirtualMFADeviceCommand,
  DetachGroupPolicyCommand,
  DetachRolePolicyCommand,
  DetachUserPolicyCommand,
  GetInstanceProfileCommand,
  ListAccessKeysCommand,
  ListMFADevicesCommand,
  ListServiceSpecificCredentialsCommand,
  ListSigningCertificatesCommand,
  ListSSHPublicKeysCommand,
  PutGroupPolicyCommand,
  PutRolePermissionsBoundaryCommand,
  PutRolePolicyCommand,
  PutUserPermissionsBoundaryCommand,
  PutUserPolicyCommand,
  RemoveRoleFromInstanceProfileCommand,
  RemoveUserFromGroupCommand,
  SetDefaultPolicyVersionCommand,
  TagInstanceProfileCommand,
  TagPolicyCommand,
  TagRoleCommand,
  TagUserCommand,
  UntagInstanceProfileCommand,
  UntagPolicyCommand,
  UntagRoleCommand,
  UntagUserCommand,
  UpdateAccessKeyCommand,
  UpdateAccountPasswordPolicyCommand,
  UpdateAssumeRolePolicyCommand,
  UpdateGroupCommand,
  UpdateLoginProfileCommand,
  UpdateRoleCommand,
  UpdateUserCommand,
  type IAMClient,
} from "@aws-sdk/client-iam";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { iam } from "../../lib/clients";
import {
  attachedPolicies,
  groupMembers,
  groupsForUser,
  inlinePolicies,
  instanceProfilesForRole,
  parseTags,
  policyEntities,
  policyVersions,
  type Kind,
} from "../../lib/iam";

export type { Kind };

const page = (kind: Kind, name: string) => `/iam/${kind}s/${encodeURIComponent(name)}`;
const policyPage = (arn: string) => `/iam/policy?arn=${encodeURIComponent(arn)}`;
const profilePage = (name: string) => `/iam/instance-profiles/${encodeURIComponent(name)}`;

function json(form: FormData, field: string, label: string) {
  const value = required(form, field, label);
  try {
    JSON.parse(value);
  } catch {
    throw new FieldError(field, "Invalid JSON", "format");
  }
  return value;
}

/** Where IAM's policy errors land: the form's document field. */
const document = (field: string) => ({ PolicyDocument: field, MalformedPolicyDocumentException: field });

/** Ignore "it is not there": cleanup steps race with what is already gone. */
async function gone(run: Promise<unknown>) {
  try {
    await run;
  } catch (e) {
    if ((e as { name?: string }).name !== "NoSuchEntityException") throw e;
  }
}

export async function createUser(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "User name");
    await (await iam()).send(new CreateUserCommand({ UserName: name, Path: text(form, "path") || undefined }));
    return `Created ${name}`;
  }, { revalidate: ["/iam"], fields: { UserName: "name", Path: "path" } });
}

export async function createGroup(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Group name");
    await (await iam()).send(new CreateGroupCommand({ GroupName: name, Path: text(form, "path") || undefined }));
    return `Created ${name}`;
  }, { revalidate: ["/iam"], fields: { GroupName: "name", Path: "path" } });
}

export async function createRole(_: ActionResult | null, form: FormData) {
  // A rejected trust policy is the one typed, or else the trusted service's.
  const policy = text(form, "trust") ? "trust" : "service";
  return act(async () => {
    const name = required(form, "name", "Role name");
    const service = text(form, "service");
    const doc =
      text(form, "trust") ||
      JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Principal: { Service: service || "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }],
      });
    const client = await iam();
    await client.send(new CreateRoleCommand({ RoleName: name, AssumeRolePolicyDocument: doc, Description: text(form, "description") || undefined }));
    // The managed policies picked (the preset suggests the one that kind of role usually needs).
    const attach = [...new Set([text(form, "attach"), ...text(form, "policies").split(",")].map((p) => p.trim()).filter(Boolean))];
    for (const PolicyArn of attach) await client.send(new AttachRolePolicyCommand({ RoleName: name, PolicyArn }));
    const boundary = text(form, "boundary");
    if (boundary) await client.send(new PutRolePermissionsBoundaryCommand({ RoleName: name, PermissionsBoundary: boundary }));
    if (attach.length) return `Created ${name} with ${attach.map((a) => a.split("/").pop()).join(", ")}`;
    return `Created ${name}`;
  }, { revalidate: ["/iam"], fields: { RoleName: "name", Description: "description", AssumeRolePolicyDocument: policy, MalformedPolicyDocumentException: policy } });
}

export async function createPolicy(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Policy name");
    await (await iam()).send(
      new CreatePolicyCommand({ PolicyName: name, PolicyDocument: json(form, "document", "Policy document"), Description: text(form, "description") || undefined }),
    );
    return `Created ${name}`;
  }, { revalidate: ["/iam"], fields: { PolicyName: "name", Description: "description", ...document("document") } });
}

/** AWS's console deletes a policy in one go: it detaches it from every
 * entity and deletes its other versions first. */
export async function deletePolicy(arn: string) {
  return act(async () => {
    const client = await iam();
    const [{ roles, users, groups }, versions] = await Promise.all([policyEntities(client, arn), policyVersions(client, arn)]);
    await Promise.all([
      ...roles.map((r) => gone(client.send(new DetachRolePolicyCommand({ RoleName: r.RoleName, PolicyArn: arn })))),
      ...users.map((u) => gone(client.send(new DetachUserPolicyCommand({ UserName: u.UserName, PolicyArn: arn })))),
      ...groups.map((g) => gone(client.send(new DetachGroupPolicyCommand({ GroupName: g.GroupName, PolicyArn: arn })))),
    ]);
    for (const v of versions.filter((v) => !v.IsDefaultVersion)) await gone(client.send(new DeletePolicyVersionCommand({ PolicyArn: arn, VersionId: v.VersionId })));
    await client.send(new DeletePolicyCommand({ PolicyArn: arn }));
    redirect("/iam?tab=policies");
  });
}

/** Save an edited document as a new version. IAM keeps at most five, so
 * the oldest version that is not the default makes room, as AWS's console
 * offers. */
export async function createPolicyVersion(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await iam();
    const PolicyDocument = json(form, "document", "Policy document");
    const SetAsDefault = form.get("default") === "on";
    const versions = await policyVersions(client, arn);
    let pruned: string | undefined;
    if (versions.length >= 5) {
      const oldest = versions.filter((v) => !v.IsDefaultVersion).sort((a, b) => +new Date(a.CreateDate!) - +new Date(b.CreateDate!))[0];
      if (oldest) {
        await client.send(new DeletePolicyVersionCommand({ PolicyArn: arn, VersionId: oldest.VersionId }));
        pruned = oldest.VersionId;
      }
    }
    const out = await client.send(new CreatePolicyVersionCommand({ PolicyArn: arn, PolicyDocument, SetAsDefault }));
    const id = out.PolicyVersion?.VersionId;
    return `Saved ${id}${SetAsDefault ? " as the default" : ""}${pruned ? `, deleted ${pruned}` : ""}`;
  }, { revalidate: [policyPage(arn)], fields: { ...document("document"), LimitExceededException: "document" } });
}

export async function setDefaultVersion(arn: string, version: string) {
  return act(async () => {
    await (await iam()).send(new SetDefaultPolicyVersionCommand({ PolicyArn: arn, VersionId: version }));
    return `${version} is the default`;
  }, policyPage(arn));
}

export async function deletePolicyVersion(arn: string, version: string) {
  return act(async () => {
    await (await iam()).send(new DeletePolicyVersionCommand({ PolicyArn: arn, VersionId: version }));
    return `Deleted ${version}`;
  }, policyPage(arn));
}

export async function attachPolicy(kind: Kind, name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const PolicyArn = required(form, "policyArn", "Policy");
    const client = await iam();
    if (kind === "role") await client.send(new AttachRolePolicyCommand({ RoleName: name, PolicyArn }));
    else if (kind === "user") await client.send(new AttachUserPolicyCommand({ UserName: name, PolicyArn }));
    else await client.send(new AttachGroupPolicyCommand({ GroupName: name, PolicyArn }));
    return `Attached ${PolicyArn.split("/").pop()}`;
  }, { revalidate: [page(kind, name)], fields: { PolicyArn: "policyArn", NoSuchEntityException: "policyArn", InvalidInputException: "policyArn" } });
}

export async function detachPolicy(kind: Kind, name: string, PolicyArn: string) {
  return act(async () => {
    const client = await iam();
    if (kind === "role") await client.send(new DetachRolePolicyCommand({ RoleName: name, PolicyArn }));
    else if (kind === "user") await client.send(new DetachUserPolicyCommand({ UserName: name, PolicyArn }));
    else await client.send(new DetachGroupPolicyCommand({ GroupName: name, PolicyArn }));
    return "Detached";
  }, page(kind, name));
}

async function putInline(client: IAMClient, kind: Kind, name: string, PolicyName: string, PolicyDocument: string) {
  if (kind === "role") await client.send(new PutRolePolicyCommand({ RoleName: name, PolicyName, PolicyDocument }));
  else if (kind === "user") await client.send(new PutUserPolicyCommand({ UserName: name, PolicyName, PolicyDocument }));
  else await client.send(new PutGroupPolicyCommand({ GroupName: name, PolicyName, PolicyDocument }));
}

async function deleteInline(client: IAMClient, kind: Kind, name: string, PolicyName: string) {
  if (kind === "role") await client.send(new DeleteRolePolicyCommand({ RoleName: name, PolicyName }));
  else if (kind === "user") await client.send(new DeleteUserPolicyCommand({ UserName: name, PolicyName }));
  else await client.send(new DeleteGroupPolicyCommand({ GroupName: name, PolicyName }));
}

export async function putInlinePolicy(kind: Kind, name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const PolicyName = required(form, "policyName", "Policy name");
    const PolicyDocument = json(form, "document", "Policy document");
    await putInline(await iam(), kind, name, PolicyName, PolicyDocument);
    return `Saved ${PolicyName}`;
  }, { revalidate: [page(kind, name), `${page(kind, name)}/inline/${encodeURIComponent(text(form, "policyName"))}`], fields: { PolicyName: "policyName", ...document("document") } });
}

/** Save an existing inline policy's document (its name stays). */
export async function updateInlinePolicy(kind: Kind, name: string, PolicyName: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await putInline(await iam(), kind, name, PolicyName, json(form, "document", "Policy document"));
    return `Saved ${PolicyName}`;
  }, { revalidate: [`${page(kind, name)}/inline/${encodeURIComponent(PolicyName)}`, page(kind, name)], fields: document("document") });
}

export async function deleteInlinePolicy(kind: Kind, name: string, PolicyName: string, back?: boolean) {
  return act(async () => {
    await deleteInline(await iam(), kind, name, PolicyName);
    if (back) redirect(page(kind, name));
    return `Deleted ${PolicyName}`;
  }, page(kind, name));
}

export async function updateTrust(role: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await iam()).send(new UpdateAssumeRolePolicyCommand({ RoleName: role, PolicyDocument: json(form, "document", "Trust policy") }));
    return "Trust policy saved";
  }, { revalidate: [page("role", role)], fields: document("document") });
}

export async function updateRole(role: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const hours = Number(text(form, "hours") || 1);
    await (await iam()).send(new UpdateRoleCommand({ RoleName: role, Description: text(form, "description"), MaxSessionDuration: Math.round(hours * 3600) }));
    return "Role saved";
  }, { revalidate: [page("role", role)], fields: { Description: "description", MaxSessionDuration: "hours" } });
}

/** Rename a user or group, or move it to another path. */
export async function renamePrincipal(kind: "user" | "group", name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const next = required(form, "name", "Name");
    const NewPath = text(form, "path") || undefined;
    const client = await iam();
    const NewName = next !== name ? next : undefined;
    if (kind === "user") await client.send(new UpdateUserCommand({ UserName: name, NewUserName: NewName, NewPath }));
    else await client.send(new UpdateGroupCommand({ GroupName: name, NewGroupName: NewName, NewPath }));
    if (NewName) redirect(page(kind, next));
    return "Saved";
  }, { revalidate: ["/iam", page(kind, name)], fields: { NewUserName: "name", NewGroupName: "name", NewPath: "path", EntityAlreadyExistsException: "name" } });
}

export async function putBoundary(kind: "role" | "user", name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const PermissionsBoundary = required(form, "policyArn", "Policy");
    const client = await iam();
    if (kind === "role") await client.send(new PutRolePermissionsBoundaryCommand({ RoleName: name, PermissionsBoundary }));
    else await client.send(new PutUserPermissionsBoundaryCommand({ UserName: name, PermissionsBoundary }));
    return "Boundary set";
  }, { revalidate: [page(kind, name)], fields: { PermissionsBoundary: "policyArn", NoSuchEntityException: "policyArn", InvalidInputException: "policyArn" } });
}

export async function deleteBoundary(kind: "role" | "user", name: string) {
  return act(async () => {
    const client = await iam();
    if (kind === "role") await client.send(new DeleteRolePermissionsBoundaryCommand({ RoleName: name }));
    else await client.send(new DeleteUserPermissionsBoundaryCommand({ UserName: name }));
    return "Boundary removed";
  }, page(kind, name));
}

export type Taggable = "role" | "user" | "policy" | "instance-profile";

/** Replace a resource's tags with the `key=value` lines of the form. */
export async function saveTags(kind: Taggable, id: string, current: string[], _: ActionResult | null, form: FormData) {
  const path = kind === "policy" ? policyPage(id) : kind === "instance-profile" ? profilePage(id) : page(kind, id);
  return act(async () => {
    const Tags = parseTags(text(form, "tags"));
    const TagKeys = current.filter((k) => !Tags.some((t) => t.Key === k));
    const client = await iam();
    if (TagKeys.length) {
      if (kind === "role") await client.send(new UntagRoleCommand({ RoleName: id, TagKeys }));
      else if (kind === "user") await client.send(new UntagUserCommand({ UserName: id, TagKeys }));
      else if (kind === "policy") await client.send(new UntagPolicyCommand({ PolicyArn: id, TagKeys }));
      else await client.send(new UntagInstanceProfileCommand({ InstanceProfileName: id, TagKeys }));
    }
    if (Tags.length) {
      if (kind === "role") await client.send(new TagRoleCommand({ RoleName: id, Tags }));
      else if (kind === "user") await client.send(new TagUserCommand({ UserName: id, Tags }));
      else if (kind === "policy") await client.send(new TagPolicyCommand({ PolicyArn: id, Tags }));
      else await client.send(new TagInstanceProfileCommand({ InstanceProfileName: id, Tags }));
    }
    return "Tags saved";
  }, { revalidate: [path], fields: { Tags: "tags", TagKeys: "tags", InvalidInputException: "tags", LimitExceededException: "tags" } });
}

export async function createAccessKey(user: string) {
  return act(async () => {
    const out = await (await iam()).send(new CreateAccessKeyCommand({ UserName: user }));
    return {
      ok: true,
      message: "Copy the secret now: it is not shown again",
      detail: `AWS_ACCESS_KEY_ID=${out.AccessKey!.AccessKeyId}\nAWS_SECRET_ACCESS_KEY=${out.AccessKey!.SecretAccessKey}`,
    };
  }, page("user", user));
}

export async function setAccessKey(user: string, id: string, active: boolean) {
  return act(async () => {
    await (await iam()).send(new UpdateAccessKeyCommand({ UserName: user, AccessKeyId: id, Status: active ? "Active" : "Inactive" }));
    return active ? "Activated" : "Deactivated";
  }, page("user", user));
}

export async function deleteAccessKey(user: string, id: string) {
  return act(async () => {
    await (await iam()).send(new DeleteAccessKeyCommand({ UserName: user, AccessKeyId: id }));
    return "Deleted";
  }, page("user", user));
}

/** Console password: create it, or set a new one when it exists. */
export async function saveLoginProfile(user: string, exists: boolean, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Password = required(form, "password", "Password");
    const PasswordResetRequired = form.get("reset") === "on";
    const client = await iam();
    if (exists) await client.send(new UpdateLoginProfileCommand({ UserName: user, Password, PasswordResetRequired }));
    else await client.send(new CreateLoginProfileCommand({ UserName: user, Password, PasswordResetRequired }));
    return exists ? "Password changed" : "Console access enabled";
  }, { revalidate: [page("user", user)], fields: { Password: "password", PasswordPolicyViolationException: "password" } });
}

export async function deleteLoginProfile(user: string) {
  return act(async () => {
    await (await iam()).send(new DeleteLoginProfileCommand({ UserName: user }));
    return "Console access disabled";
  }, page("user", user));
}

/** Deactivate an MFA device; a virtual one is deleted too, as AWS's console does. */
export async function removeMfa(user: string, serial: string) {
  return act(async () => {
    const client = await iam();
    await client.send(new DeactivateMFADeviceCommand({ UserName: user, SerialNumber: serial }));
    if (serial.startsWith("arn:")) await gone(client.send(new DeleteVirtualMFADeviceCommand({ SerialNumber: serial })));
    return "MFA device removed";
  }, page("user", user));
}

export async function addToGroup(user: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const group = required(form, "group", "Group");
    await (await iam()).send(new AddUserToGroupCommand({ UserName: user, GroupName: group }));
    return `Added to ${group}`;
  }, { revalidate: [page("user", user), page("group", text(form, "group"))], fields: { GroupName: "group", NoSuchEntityException: "group" } });
}

export async function addMember(group: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const user = required(form, "user", "User");
    await (await iam()).send(new AddUserToGroupCommand({ UserName: user, GroupName: group }));
    return `Added ${user}`;
  }, { revalidate: [page("group", group), page("user", text(form, "user"))], fields: { UserName: "user", NoSuchEntityException: "user" } });
}

export async function removeFromGroup(user: string, group: string) {
  return act(async () => {
    await (await iam()).send(new RemoveUserFromGroupCommand({ UserName: user, GroupName: group }));
    return `Removed ${user} from ${group}`;
  }, page("user", user), page("group", group));
}

export async function createInstanceProfile(role: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const InstanceProfileName = required(form, "name", "Name");
    const client = await iam();
    await client.send(new CreateInstanceProfileCommand({ InstanceProfileName, Path: text(form, "path") || undefined }));
    await client.send(new AddRoleToInstanceProfileCommand({ InstanceProfileName, RoleName: role }));
    return `Created ${InstanceProfileName}`;
  }, { revalidate: [page("role", role)], fields: { InstanceProfileName: "name", Path: "path" } });
}

export async function addRoleToProfile(profile: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const role = required(form, "role", "Role");
    await (await iam()).send(new AddRoleToInstanceProfileCommand({ InstanceProfileName: profile, RoleName: role }));
    return `Added ${role}`;
  }, { revalidate: [profilePage(profile)], fields: { RoleName: "role", NoSuchEntityException: "role", LimitExceededException: "role" } });
}

export async function removeRoleFromProfile(profile: string, role: string) {
  return act(async () => {
    await (await iam()).send(new RemoveRoleFromInstanceProfileCommand({ InstanceProfileName: profile, RoleName: role }));
    return `Removed ${role}`;
  }, page("role", role), profilePage(profile));
}

export async function deleteInstanceProfile(name: string) {
  return act(async () => {
    const client = await iam();
    const profile = (await client.send(new GetInstanceProfileCommand({ InstanceProfileName: name }))).InstanceProfile;
    for (const r of profile?.Roles ?? []) await gone(client.send(new RemoveRoleFromInstanceProfileCommand({ InstanceProfileName: name, RoleName: r.RoleName })));
    await client.send(new DeleteInstanceProfileCommand({ InstanceProfileName: name }));
    redirect("/iam?tab=roles");
  });
}

/** Everything IAM refuses to delete a user over, removed first as AWS's
 * console does: keys, password, MFA, groups, policies and other credentials. */
async function emptyUser(client: IAMClient, name: string) {
  const UserName = name;
  const [keys, mfa, groups, attached, inline, ssh, certs, creds] = await Promise.all([
    client.send(new ListAccessKeysCommand({ UserName })).then((r) => r.AccessKeyMetadata ?? []),
    client.send(new ListMFADevicesCommand({ UserName })).then((r) => r.MFADevices ?? []),
    groupsForUser(client, name),
    attachedPolicies(client, "user", name),
    inlinePolicies(client, "user", name),
    client.send(new ListSSHPublicKeysCommand({ UserName })).then((r) => r.SSHPublicKeys ?? [], () => []),
    client.send(new ListSigningCertificatesCommand({ UserName })).then((r) => r.Certificates ?? [], () => []),
    client.send(new ListServiceSpecificCredentialsCommand({ UserName })).then((r) => r.ServiceSpecificCredentials ?? [], () => []),
  ]);
  await Promise.all([
    ...keys.map((k) => gone(client.send(new DeleteAccessKeyCommand({ UserName, AccessKeyId: k.AccessKeyId })))),
    gone(client.send(new DeleteLoginProfileCommand({ UserName }))),
    ...mfa.map(async (d) => {
      await gone(client.send(new DeactivateMFADeviceCommand({ UserName, SerialNumber: d.SerialNumber })));
      if (d.SerialNumber?.startsWith("arn:")) await gone(client.send(new DeleteVirtualMFADeviceCommand({ SerialNumber: d.SerialNumber })));
    }),
    ...groups.map((g) => gone(client.send(new RemoveUserFromGroupCommand({ UserName, GroupName: g.GroupName })))),
    ...attached.map((p) => gone(client.send(new DetachUserPolicyCommand({ UserName, PolicyArn: p.PolicyArn })))),
    ...inline.map((p) => gone(client.send(new DeleteUserPolicyCommand({ UserName, PolicyName: p })))),
    ...ssh.map((k) => gone(client.send(new DeleteSSHPublicKeyCommand({ UserName, SSHPublicKeyId: k.SSHPublicKeyId })))),
    ...certs.map((c) => gone(client.send(new DeleteSigningCertificateCommand({ UserName, CertificateId: c.CertificateId })))),
    ...creds.map((c) => gone(client.send(new DeleteServiceSpecificCredentialCommand({ UserName, ServiceSpecificCredentialId: c.ServiceSpecificCredentialId })))),
  ]);
}

/** A role's policies and instance profiles; a profile left empty that
 * carries the role's name (the one AWS's console made with it) goes too. */
async function emptyRole(client: IAMClient, name: string) {
  const RoleName = name;
  const [attached, inline, profiles] = await Promise.all([attachedPolicies(client, "role", name), inlinePolicies(client, "role", name), instanceProfilesForRole(client, name)]);
  await Promise.all([
    ...attached.map((p) => gone(client.send(new DetachRolePolicyCommand({ RoleName, PolicyArn: p.PolicyArn })))),
    ...inline.map((p) => gone(client.send(new DeleteRolePolicyCommand({ RoleName, PolicyName: p })))),
    ...profiles.map(async (p) => {
      await gone(client.send(new RemoveRoleFromInstanceProfileCommand({ RoleName, InstanceProfileName: p.InstanceProfileName })));
      if (p.InstanceProfileName === name && (p.Roles ?? []).length <= 1) await gone(client.send(new DeleteInstanceProfileCommand({ InstanceProfileName: p.InstanceProfileName })));
    }),
  ]);
}

async function emptyGroup(client: IAMClient, name: string) {
  const GroupName = name;
  const [members, attached, inline] = await Promise.all([groupMembers(client, name), attachedPolicies(client, "group", name), inlinePolicies(client, "group", name)]);
  await Promise.all([
    ...members.map((u) => gone(client.send(new RemoveUserFromGroupCommand({ GroupName, UserName: u.UserName })))),
    ...attached.map((p) => gone(client.send(new DetachGroupPolicyCommand({ GroupName, PolicyArn: p.PolicyArn })))),
    ...inline.map((p) => gone(client.send(new DeleteGroupPolicyCommand({ GroupName, PolicyName: p })))),
  ]);
}

export async function deletePrincipal(kind: Kind, name: string) {
  return act(async () => {
    const client = await iam();
    if (kind === "role") {
      await emptyRole(client, name);
      await client.send(new DeleteRoleCommand({ RoleName: name }));
    } else if (kind === "user") {
      await emptyUser(client, name);
      await client.send(new DeleteUserCommand({ UserName: name }));
    } else {
      await emptyGroup(client, name);
      await client.send(new DeleteGroupCommand({ GroupName: name }));
    }
    redirect(kind === "user" ? "/iam" : `/iam?tab=${kind}s`);
  });
}

/** Service-linked roles go through the service: the deletion is a task
 * whose status the role page follows. */
export async function deleteServiceLinkedRole(name: string) {
  return act(async () => {
    const out = await (await iam()).send(new DeleteServiceLinkedRoleCommand({ RoleName: name }));
    redirect(`${page("role", name)}?deletion=${encodeURIComponent(out.DeletionTaskId!)}`);
  });
}

export async function createAccountAlias(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const AccountAlias = required(form, "alias", "Alias");
    await (await iam()).send(new CreateAccountAliasCommand({ AccountAlias }));
    return `Alias ${AccountAlias} set`;
  }, { revalidate: ["/iam/settings"], fields: { AccountAlias: "alias", EntityAlreadyExistsException: "alias" } });
}

export async function deleteAccountAlias(alias: string) {
  return act(async () => {
    await (await iam()).send(new DeleteAccountAliasCommand({ AccountAlias: alias }));
    return "Alias removed";
  }, "/iam/settings");
}

export async function savePasswordPolicy(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const num = (name: string) => (text(form, name) ? Number(text(form, name)) : undefined);
    const on = (name: string) => form.get(name) === "on";
    await (await iam()).send(
      new UpdateAccountPasswordPolicyCommand({
        MinimumPasswordLength: num("length"),
        RequireUppercaseCharacters: on("upper"),
        RequireLowercaseCharacters: on("lower"),
        RequireNumbers: on("numbers"),
        RequireSymbols: on("symbols"),
        AllowUsersToChangePassword: on("change"),
        MaxPasswordAge: num("age"),
        PasswordReusePrevention: num("reuse"),
        HardExpiry: on("expiry"),
      }),
    );
    return "Password policy saved";
  }, { revalidate: ["/iam/settings"], fields: { MinimumPasswordLength: "length", MaxPasswordAge: "age", PasswordReusePrevention: "reuse" } });
}

export async function deletePasswordPolicy() {
  return act(async () => {
    await (await iam()).send(new DeleteAccountPasswordPolicyCommand({}));
    return "Back to the AWS default";
  }, "/iam/settings");
}

export async function createOidcProvider(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const list = (field: string) => text(form, field).split(/[\s,]+/).filter(Boolean);
    const Url = required(form, "url", "Provider URL");
    await (await iam()).send(new CreateOpenIDConnectProviderCommand({ Url, ClientIDList: list("clients"), ThumbprintList: list("thumbprints").length ? list("thumbprints") : undefined }));
    return `Added ${Url}`;
  }, { revalidate: ["/iam/providers"], fields: { Url: "url", ClientIDList: "clients", ThumbprintList: "thumbprints", EntityAlreadyExistsException: "url" } });
}

export async function createSamlProvider(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Name");
    await (await iam()).send(new CreateSAMLProviderCommand({ Name, SAMLMetadataDocument: required(form, "metadata", "Metadata document") }));
    return `Added ${Name}`;
  }, { revalidate: ["/iam/providers"], fields: { Name: "name", SAMLMetadataDocument: "metadata", EntityAlreadyExistsException: "name" } });
}

export async function deleteProvider(arn: string) {
  return act(async () => {
    const client = await iam();
    if (arn.includes(":oidc-provider/")) await client.send(new DeleteOpenIDConnectProviderCommand({ OpenIDConnectProviderArn: arn }));
    else await client.send(new DeleteSAMLProviderCommand({ SAMLProviderArn: arn }));
    return "Provider deleted";
  }, "/iam/providers");
}
