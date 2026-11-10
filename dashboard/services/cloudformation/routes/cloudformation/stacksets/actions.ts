"use server";

import {
  CreateStackInstancesCommand,
  CreateStackSetCommand,
  DeleteStackInstancesCommand,
  DeleteStackSetCommand,
  DetectStackSetDriftCommand,
  StopStackSetOperationCommand,
  UpdateStackSetCommand,
  type Capability,
} from "@aws-sdk/client-cloudformation";
import { act, frameInfo, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { wantsAuto } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { cloudformation } from "../../../lib/clients";
import { EXECUTION_ROLE, ensureStackSetRoles } from "../../../lib/stacksets";

const enc = encodeURIComponent;
const list = (form: FormData, name: string) =>
  text(form, name)
    .split(/[\s,]+/)
    .filter(Boolean);
const parameters = (form: FormData, keep: boolean) =>
  text(form, "parameters")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.includes("="))
    .map((l) => {
      const key = l.slice(0, l.indexOf("=")).trim();
      const value = l.slice(l.indexOf("=") + 1).trim();
      return keep && value === "****" ? { ParameterKey: key, UsePreviousValue: true } : { ParameterKey: key, ParameterValue: value };
    });
const capabilities = (form: FormData) => form.getAll("capabilities").map(String) as Capability[];
const FIELDS = { StackSetName: "name", TemplateBody: "template", Parameters: "parameters", Accounts: "accounts", Regions: "regions", AdministrationRoleARN: "adminRole", ExecutionRoleName: "executionRole" };
const href = (name: string, tab?: string) => `/cloudformation/stackset?name=${enc(name)}${tab ? `&tab=${tab}` : ""}`;

export async function createStackSet(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const StackSetName = required(form, "name", "StackSet name");
      const account = (await frameInfo()).account ?? "";
      const AdministrationRoleARN = wantsAuto(form, "adminRole") ? await ensureStackSetRoles(account) : text(form, "adminRole");
      const client = await cloudformation();
      await client.send(
        new CreateStackSetCommand({
          StackSetName,
          Description: text(form, "description") || undefined,
          TemplateBody: required(form, "template", "Template"),
          Parameters: parameters(form, false),
          Capabilities: capabilities(form),
          PermissionModel: "SELF_MANAGED",
          AdministrationRoleARN,
          ExecutionRoleName: text(form, "executionRole") || EXECUTION_ROLE,
        }),
      );
      const regions = list(form, "regions");
      if (regions.length) {
        const accounts = list(form, "accounts");
        await client.send(new CreateStackInstancesCommand({ StackSetName, Accounts: accounts.length ? accounts : [account], Regions: regions }));
      }
      redirect(href(StackSetName, regions.length ? "operations" : undefined));
    },
    { fields: FIELDS },
  );
}

export async function updateStackSet(name: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      await (await cloudformation()).send(
        new UpdateStackSetCommand({ StackSetName: name, TemplateBody: required(form, "template", "Template"), Parameters: parameters(form, true), Capabilities: capabilities(form), Description: text(form, "description") || undefined }),
      );
      redirect(href(name, "operations"));
    },
    { fields: FIELDS },
  );
}

export async function addStackInstances(name: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const accounts = list(form, "accounts");
      const Regions = list(form, "regions");
      if (!Regions.length) Regions.push(await region());
      await (await cloudformation()).send(new CreateStackInstancesCommand({ StackSetName: name, Accounts: accounts.length ? accounts : [(await frameInfo()).account ?? ""], Regions }));
      redirect(href(name, "operations"));
    },
    { fields: FIELDS },
  );
}

export async function deleteStackInstance(name: string, account: string, instanceRegion: string, retain: boolean) {
  return act(async () => {
    await (await cloudformation()).send(new DeleteStackInstancesCommand({ StackSetName: name, Accounts: [account], Regions: [instanceRegion], RetainStacks: retain }));
    return `Removing ${account} / ${instanceRegion}`;
  }, "/cloudformation/stackset");
}

export async function deleteStackSet(name: string) {
  return act(async () => {
    await (await cloudformation()).send(new DeleteStackSetCommand({ StackSetName: name }));
    redirect("/cloudformation/stacksets");
  });
}

export async function detectStackSetDrift(name: string) {
  return act(async () => {
    await (await cloudformation()).send(new DetectStackSetDriftCommand({ StackSetName: name }));
    redirect(href(name, "operations"));
  });
}

export async function stopOperation(name: string, operationId: string) {
  return act(async () => {
    await (await cloudformation()).send(new StopStackSetOperationCommand({ StackSetName: name, OperationId: operationId }));
    return "Stopping";
  }, "/cloudformation/stackset");
}
