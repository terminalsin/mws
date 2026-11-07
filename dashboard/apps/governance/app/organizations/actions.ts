"use server";

import {
  AttachPolicyCommand,
  CreateAccountCommand,
  CreateOrganizationalUnitCommand,
  CreateOrganizationCommand,
  CreatePolicyCommand,
  DeleteOrganizationalUnitCommand,
  DeletePolicyCommand,
  DetachPolicyCommand,
  EnablePolicyTypeCommand,
  ListRootsCommand,
  MoveAccountCommand,
  type PolicyType,
} from "@aws-sdk/client-organizations";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";

import { organizations } from "../../lib/clients";

export async function createOrganization() {
  return act(async () => {
    await (await organizations()).send(new CreateOrganizationCommand({ FeatureSet: "ALL" }));
    return "Organization created";
  }, "/organizations");
}

export async function createAccount(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await organizations()).send(new CreateAccountCommand({ AccountName: required(form, "name", "Account name"), Email: required(form, "email", "Email") }));
    return `Creating account (${out.CreateAccountStatus?.State?.toLowerCase().replace(/_/g, " ")})`;
  }, "/organizations");
}

export async function createOu(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await organizations()).send(new CreateOrganizationalUnitCommand({ ParentId: required(form, "parent", "Parent"), Name: required(form, "name", "Name") }));
    return "Organizational unit created";
  }, "/organizations");
}

export async function deleteOu(id: string) {
  return act(async () => {
    await (await organizations()).send(new DeleteOrganizationalUnitCommand({ OrganizationalUnitId: id }));
    return "Deleted";
  }, "/organizations");
}

export async function moveAccount(account: string, from: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await organizations()).send(new MoveAccountCommand({ AccountId: account, SourceParentId: from, DestinationParentId: required(form, "to", "Destination") }));
    return "Moved";
  }, "/organizations");
}

export async function createPolicy(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Type = (text(form, "type") || "SERVICE_CONTROL_POLICY") as PolicyType;
    const client = await organizations();
    const root = (await client.send(new ListRootsCommand({}))).Roots?.[0];
    if (root && !root.PolicyTypes?.some((p) => p.Type === Type && p.Status === "ENABLED")) {
      await client.send(new EnablePolicyTypeCommand({ RootId: root.Id, PolicyType: Type }));
    }
    const content = required(form, "content", "Policy");
    JSON.parse(content);
    await client.send(new CreatePolicyCommand({ Name: required(form, "name", "Name"), Description: text(form, "description") || "", Type, Content: content }));
    return "Policy created";
  }, "/organizations");
}

export async function deletePolicy(id: string) {
  return act(async () => {
    await (await organizations()).send(new DeletePolicyCommand({ PolicyId: id }));
    return "Policy deleted";
  }, "/organizations");
}

export async function attachPolicy(policy: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await organizations()).send(new AttachPolicyCommand({ PolicyId: policy, TargetId: required(form, "target", "Target") }));
    return "Attached";
  }, "/organizations");
}

export async function detachPolicy(policy: string, target: string) {
  return act(async () => {
    await (await organizations()).send(new DetachPolicyCommand({ PolicyId: policy, TargetId: target }));
    return "Detached";
  }, "/organizations");
}
