"use server";

import {
  AttachPolicyCommand,
  CreateAccountCommand,
  CreateOrganizationalUnitCommand,
  CreateOrganizationCommand,
  CreatePolicyCommand,
  DeleteOrganizationalUnitCommand,
  DescribeCreateAccountStatusCommand,
  DeletePolicyCommand,
  DetachPolicyCommand,
  EnablePolicyTypeCommand,
  ListRootsCommand,
  MoveAccountCommand,
  type PolicyType,
} from "@aws-sdk/client-organizations";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";

import { organizations } from "../../lib/clients";

export async function createOrganization() {
  return act(async () => {
    await (await organizations()).send(new CreateOrganizationCommand({ FeatureSet: "ALL" }));
    return "Organization created";
  }, "/organizations");
}

export async function createAccount(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await organizations();
    const out = await client.send(new CreateAccountCommand({ AccountName: required(form, "name", "Account name"), Email: required(form, "email", "Email") }));
    // AWS accepts the request and fails it later: look once, so a taken
    // address lands on its field instead of in a status nobody opens.
    const id = out.CreateAccountStatus?.Id;
    const status = id ? ((await client.send(new DescribeCreateAccountStatusCommand({ CreateAccountRequestId: id }))).CreateAccountStatus ?? out.CreateAccountStatus) : out.CreateAccountStatus;
    if (status?.State === "FAILED") {
      if (status.FailureReason === "EMAIL_ALREADY_EXISTS") throw new FieldError("email", "Another account uses this address", "taken");
      throw new Error(`Account creation failed: ${status.FailureReason?.toLowerCase().replace(/_/g, " ") ?? "unknown reason"}`);
    }
    return `Creating account (${status?.State?.toLowerCase().replace(/_/g, " ")})`;
  }, { revalidate: ["/organizations"], fields: { AccountName: "name", Email: "email" } });
}

export async function createOu(_: ActionResult | null, form: FormData) {
  return act(async () => {
    try {
      await (await organizations()).send(new CreateOrganizationalUnitCommand({ ParentId: required(form, "parent", "Parent"), Name: required(form, "name", "Name") }));
    } catch (e) {
      if (constraint(e) === "OU_DEPTH_LIMIT_EXCEEDED") throw new FieldError("parent", "Too deep: OUs nest at most 5 levels");
      throw e;
    }
    return "Organizational unit created";
  }, { revalidate: ["/organizations"], fields: { Name: "name", ParentId: "parent", ParentNotFoundException: "parent" } });
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
  }, { revalidate: ["/organizations"], fields: { DestinationParentId: "to", DestinationParentNotFoundException: "to" } });
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
    try {
      JSON.parse(content);
    } catch (e) {
      throw new FieldError("content", e instanceof Error ? e.message : "Not JSON", "format");
    }
    try {
      await client.send(new CreatePolicyCommand({ Name: required(form, "name", "Name"), Description: text(form, "description") || "", Type, Content: content }));
    } catch (e) {
      if (constraint(e) === "POLICY_CONTENT_LIMIT_EXCEEDED") throw new FieldError("content", "Larger than the policy size limit", "tooLong");
      throw e;
    }
    return "Policy created";
  }, { revalidate: ["/organizations"], fields: { Name: "name", Description: "description", Content: "content", MalformedPolicyDocumentException: "content" } });
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
  }, { revalidate: ["/organizations"], fields: { TargetId: "target", TargetNotFoundException: "target", DuplicatePolicyAttachmentException: "target" } });
}

export async function detachPolicy(policy: string, target: string) {
  return act(async () => {
    await (await organizations()).send(new DetachPolicyCommand({ PolicyId: policy, TargetId: target }));
    return "Detached";
  }, "/organizations");
}

/** The reason of a ConstraintViolationException, if `e` is one. */
function constraint(e: unknown): string | undefined {
  return e instanceof Error && e.name === "ConstraintViolationException" ? (e as Error & { Reason?: string }).Reason : undefined;
}
