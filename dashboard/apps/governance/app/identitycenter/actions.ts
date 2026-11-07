"use server";

import { CreateGroupCommand, CreateUserCommand, DeleteGroupCommand, DeleteUserCommand } from "@aws-sdk/client-identitystore";
import { AttachManagedPolicyToPermissionSetCommand, CreateInstanceCommand, CreatePermissionSetCommand, DeletePermissionSetCommand } from "@aws-sdk/client-sso-admin";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";

import { identitystore, ssoAdmin } from "../../lib/clients";

export async function enableInstance() {
  return act(async () => {
    await (await ssoAdmin()).send(new CreateInstanceCommand({ Name: "default" }));
    return "Identity Center enabled";
  }, "/identitycenter");
}

export async function createUser(store: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const UserName = required(form, "username", "Username");
    const given = required(form, "given", "First name");
    const family = required(form, "family", "Last name");
    await (await identitystore()).send(
      new CreateUserCommand({ IdentityStoreId: store, UserName, DisplayName: `${given} ${family}`, Name: { GivenName: given, FamilyName: family }, Emails: text(form, "email") ? [{ Value: text(form, "email"), Primary: true, Type: "work" }] : undefined }),
    );
    return `Added ${UserName}`;
  }, "/identitycenter");
}

export async function deleteUser(store: string, id: string) {
  return act(async () => {
    await (await identitystore()).send(new DeleteUserCommand({ IdentityStoreId: store, UserId: id }));
    return "User deleted";
  }, "/identitycenter");
}

export async function createGroup(store: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const DisplayName = required(form, "name", "Group name");
    await (await identitystore()).send(new CreateGroupCommand({ IdentityStoreId: store, DisplayName, Description: text(form, "description") || undefined }));
    return `Created ${DisplayName}`;
  }, "/identitycenter");
}

export async function deleteGroup(store: string, id: string) {
  return act(async () => {
    await (await identitystore()).send(new DeleteGroupCommand({ IdentityStoreId: store, GroupId: id }));
    return "Group deleted";
  }, "/identitycenter");
}

export async function createPermissionSet(instance: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Name");
    const client = await ssoAdmin();
    const out = await client.send(new CreatePermissionSetCommand({ InstanceArn: instance, Name, SessionDuration: `PT${text(form, "hours") || 1}H`, Description: text(form, "description") || undefined }));
    const policy = text(form, "policy");
    if (policy) await client.send(new AttachManagedPolicyToPermissionSetCommand({ InstanceArn: instance, PermissionSetArn: out.PermissionSet!.PermissionSetArn, ManagedPolicyArn: policy }));
    return `Created ${Name}`;
  }, "/identitycenter");
}

export async function deletePermissionSet(instance: string, arn: string) {
  return act(async () => {
    await (await ssoAdmin()).send(new DeletePermissionSetCommand({ InstanceArn: instance, PermissionSetArn: arn }));
    return "Permission set deleted";
  }, "/identitycenter");
}
