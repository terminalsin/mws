"use server";

import {
  AddUserToGroupCommand,
  AttachGroupPolicyCommand,
  AttachRolePolicyCommand,
  AttachUserPolicyCommand,
  CreateAccessKeyCommand,
  CreateGroupCommand,
  CreatePolicyCommand,
  CreateRoleCommand,
  CreateUserCommand,
  DeleteAccessKeyCommand,
  DeleteGroupCommand,
  DeletePolicyCommand,
  DeleteRoleCommand,
  DeleteRolePolicyCommand,
  DeleteUserCommand,
  DeleteUserPolicyCommand,
  DetachGroupPolicyCommand,
  DetachRolePolicyCommand,
  DetachUserPolicyCommand,
  PutRolePolicyCommand,
  PutUserPolicyCommand,
  RemoveUserFromGroupCommand,
  UpdateAccessKeyCommand,
  UpdateAssumeRolePolicyCommand,
} from "@aws-sdk/client-iam";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { iam } from "../../lib/clients";

export type Kind = "role" | "user" | "group";
const page = (kind: Kind, name: string) => `/iam/${kind}s/${encodeURIComponent(name)}`;

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
const document = (field: string) => ({ PolicyDocument: field, MalformedPolicyDocument: field });

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
    await (await iam()).send(new CreateGroupCommand({ GroupName: name }));
    return `Created ${name}`;
  }, { revalidate: ["/iam"], fields: { GroupName: "name" } });
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
    await (await iam()).send(new CreateRoleCommand({ RoleName: name, AssumeRolePolicyDocument: doc, Description: text(form, "description") || undefined }));
    return `Created ${name}`;
  }, { revalidate: ["/iam"], fields: { RoleName: "name", AssumeRolePolicyDocument: policy, MalformedPolicyDocument: policy } });
}

export async function createPolicy(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Policy name");
    await (await iam()).send(new CreatePolicyCommand({ PolicyName: name, PolicyDocument: json(form, "document", "Policy document") }));
    return `Created ${name}`;
  }, { revalidate: ["/iam"], fields: { PolicyName: "name", ...document("document") } });
}

export async function deletePolicy(arn: string) {
  return act(async () => {
    await (await iam()).send(new DeletePolicyCommand({ PolicyArn: arn }));
    redirect("/iam?tab=policies");
  });
}

export async function attachPolicy(kind: Kind, name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const PolicyArn = required(form, "policyArn", "Policy");
    const client = await iam();
    if (kind === "role") await client.send(new AttachRolePolicyCommand({ RoleName: name, PolicyArn }));
    else if (kind === "user") await client.send(new AttachUserPolicyCommand({ UserName: name, PolicyArn }));
    else await client.send(new AttachGroupPolicyCommand({ GroupName: name, PolicyArn }));
    return `Attached ${PolicyArn.split("/").pop()}`;
  }, { revalidate: [page(kind, name)], fields: { PolicyArn: "policyArn", NoSuchEntity: "policyArn", InvalidInput: "policyArn" } });
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

export async function putInlinePolicy(kind: "role" | "user", name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const PolicyName = required(form, "policyName", "Policy name");
    const PolicyDocument = json(form, "document", "Policy document");
    const client = await iam();
    if (kind === "role") await client.send(new PutRolePolicyCommand({ RoleName: name, PolicyName, PolicyDocument }));
    else await client.send(new PutUserPolicyCommand({ UserName: name, PolicyName, PolicyDocument }));
    return `Saved ${PolicyName}`;
  }, { revalidate: [page(kind, name)], fields: { PolicyName: "policyName", ...document("document") } });
}

export async function deleteInlinePolicy(kind: "role" | "user", name: string, PolicyName: string) {
  return act(async () => {
    const client = await iam();
    if (kind === "role") await client.send(new DeleteRolePolicyCommand({ RoleName: name, PolicyName }));
    else await client.send(new DeleteUserPolicyCommand({ UserName: name, PolicyName }));
    return `Deleted ${PolicyName}`;
  }, page(kind, name));
}

export async function updateTrust(role: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await iam()).send(new UpdateAssumeRolePolicyCommand({ RoleName: role, PolicyDocument: json(form, "document", "Trust policy") }));
    return "Trust policy saved";
  }, { revalidate: [page("role", role)], fields: document("document") });
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

export async function addToGroup(user: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const group = required(form, "group", "Group");
    await (await iam()).send(new AddUserToGroupCommand({ UserName: user, GroupName: group }));
    return `Added to ${group}`;
  }, { revalidate: [page("user", user)], fields: { GroupName: "group", NoSuchEntity: "group" } });
}

export async function removeFromGroup(user: string, group: string) {
  return act(async () => {
    await (await iam()).send(new RemoveUserFromGroupCommand({ UserName: user, GroupName: group }));
    return `Removed from ${group}`;
  }, page("user", user));
}

export async function deletePrincipal(kind: Kind, name: string) {
  return act(async () => {
    const client = await iam();
    if (kind === "role") await client.send(new DeleteRoleCommand({ RoleName: name }));
    else if (kind === "user") await client.send(new DeleteUserCommand({ UserName: name }));
    else await client.send(new DeleteGroupCommand({ GroupName: name }));
    redirect(kind === "user" ? "/iam" : `/iam?tab=${kind}s`);
  });
}
