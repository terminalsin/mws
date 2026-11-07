"use server";

import {
  AttachRolePolicyCommand,
  AttachUserPolicyCommand,
  CreateRoleCommand,
  CreateUserCommand,
  DeleteRoleCommand,
  DeleteUserCommand,
  DetachRolePolicyCommand,
  DetachUserPolicyCommand,
} from "@aws-sdk/client-iam";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { iam } from "../../lib/clients";

export async function createUser(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "User name");
    await (await iam()).send(new CreateUserCommand({ UserName: name, Path: text(form, "path") || undefined }));
    return `Created user ${name}`;
  }, "/iam");
}

const DEFAULT_TRUST = JSON.stringify(
  { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }] },
  null,
  2,
);

export async function createRole(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Role name");
    await (await iam()).send(
      new CreateRoleCommand({ RoleName: name, AssumeRolePolicyDocument: text(form, "trust") || DEFAULT_TRUST }),
    );
    return `Created role ${name}`;
  }, "/iam");
}

export async function attachPolicy(kind: "role" | "user", name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const PolicyArn = required(form, "policyArn", "Policy ARN");
    const client = await iam();
    if (kind === "role") await client.send(new AttachRolePolicyCommand({ RoleName: name, PolicyArn }));
    else await client.send(new AttachUserPolicyCommand({ UserName: name, PolicyArn }));
    return `Attached ${PolicyArn}`;
  }, `/iam/${kind}s/${encodeURIComponent(name)}`);
}

export async function detachPolicy(kind: "role" | "user", name: string, PolicyArn: string) {
  return act(async () => {
    const client = await iam();
    if (kind === "role") await client.send(new DetachRolePolicyCommand({ RoleName: name, PolicyArn }));
    else await client.send(new DetachUserPolicyCommand({ UserName: name, PolicyArn }));
    return `Detached ${PolicyArn}`;
  }, `/iam/${kind}s/${encodeURIComponent(name)}`);
}

export async function deletePrincipal(kind: "role" | "user", name: string) {
  return act(async () => {
    const client = await iam();
    if (kind === "role") await client.send(new DeleteRoleCommand({ RoleName: name }));
    else await client.send(new DeleteUserCommand({ UserName: name }));
    redirect(kind === "role" ? "/iam?tab=roles" : "/iam");
  });
}

