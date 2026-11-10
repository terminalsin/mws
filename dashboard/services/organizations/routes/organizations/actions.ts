"use server";

import {
  AttachPolicyCommand,
  CancelHandshakeCommand,
  CloseAccountCommand,
  CreateAccountCommand,
  CreateOrganizationalUnitCommand,
  CreateOrganizationCommand,
  CreatePolicyCommand,
  DeleteOrganizationalUnitCommand,
  DescribeCreateAccountStatusCommand,
  DeletePolicyCommand,
  DeregisterDelegatedAdministratorCommand,
  DetachPolicyCommand,
  DisableAWSServiceAccessCommand,
  DisablePolicyTypeCommand,
  EnableAWSServiceAccessCommand,
  EnablePolicyTypeCommand,
  InviteAccountToOrganizationCommand,
  ListRootsCommand,
  ListTagsForResourceCommand,
  MoveAccountCommand,
  RegisterDelegatedAdministratorCommand,
  RemoveAccountFromOrganizationCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateOrganizationalUnitCommand,
  UpdatePolicyCommand,
  type PolicyType,
} from "@aws-sdk/client-organizations";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { organizations } from "../../lib/clients";
import { policyLimit } from "../../lib/organizations";

const ROOT = "/organizations";
const accountPage = (id: string) => `${ROOT}/accounts/${id}`;
const policyPage = (id: string) => `${ROOT}/policy?id=${id}`;

function content(form: FormData) {
  const value = required(form, "content", "Policy");
  try {
    JSON.parse(value);
  } catch (e) {
    throw new FieldError("content", e instanceof Error ? e.message : "Not JSON", "format");
  }
  return value;
}

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
  const Type = (text(form, "type") || "SERVICE_CONTROL_POLICY") as PolicyType;
  return act(async () => {
    const client = await organizations();
    const root = (await client.send(new ListRootsCommand({}))).Roots?.[0];
    if (root && !root.PolicyTypes?.some((p) => p.Type === Type && p.Status === "ENABLED")) {
      await client.send(new EnablePolicyTypeCommand({ RootId: root.Id, PolicyType: Type }));
    }
    const Content = content(form);
    try {
      await client.send(new CreatePolicyCommand({ Name: required(form, "name", "Name"), Description: text(form, "description") || "", Type, Content }));
    } catch (e) {
      if (constraint(e) === "POLICY_CONTENT_LIMIT_EXCEEDED") throw new FieldError("content", `Larger than ${policyLimit(Type).toLocaleString()} characters`, "tooLong");
      throw e;
    }
    return "Policy created";
  }, { revalidate: [ROOT], fields: { Name: "name", Description: "description", Content: "content", MalformedPolicyDocumentException: "content", DuplicatePolicyException: "name" } });
}

export async function updatePolicy(id: string, type: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    try {
      await (await organizations()).send(new UpdatePolicyCommand({ PolicyId: id, Name: required(form, "name", "Name"), Description: text(form, "description"), Content: content(form) }));
    } catch (e) {
      if (constraint(e) === "POLICY_CONTENT_LIMIT_EXCEEDED") throw new FieldError("content", `Larger than ${policyLimit(type).toLocaleString()} characters`, "tooLong");
      throw e;
    }
    return "Policy saved";
  }, { revalidate: [policyPage(id)], fields: { Name: "name", Description: "description", Content: "content", MalformedPolicyDocumentException: "content", DuplicatePolicyException: "name" } });
}

/** AWS refuses to delete an attached policy: detach it everywhere first, as AWS's console asks to. */
export async function deletePolicy(id: string, targets: string[] = [], back?: string) {
  return act(async () => {
    const client = await organizations();
    for (const t of targets) await client.send(new DetachPolicyCommand({ PolicyId: id, TargetId: t }));
    await client.send(new DeletePolicyCommand({ PolicyId: id }));
    if (back) redirect(back);
    return "Policy deleted";
  }, ROOT);
}

/** Attach a policy from the target's side: the form names the policy. */
export async function attachToTarget(target: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await organizations()).send(new AttachPolicyCommand({ PolicyId: required(form, "policy", "Policy"), TargetId: target }));
    return "Attached";
  }, { revalidate: [ROOT, accountPage(target)], fields: { PolicyId: "policy", PolicyNotFoundException: "policy", DuplicatePolicyAttachmentException: "policy", ConstraintViolationException: "policy" } });
}

export async function enablePolicyType(root: string, type: string) {
  return act(async () => {
    await (await organizations()).send(new EnablePolicyTypeCommand({ RootId: root, PolicyType: type as PolicyType }));
    return "Enabled";
  }, ROOT);
}

export async function disablePolicyType(root: string, type: string) {
  return act(async () => {
    await (await organizations()).send(new DisablePolicyTypeCommand({ RootId: root, PolicyType: type as PolicyType }));
    return "Disabled";
  }, ROOT);
}

export async function renameOu(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await organizations()).send(new UpdateOrganizationalUnitCommand({ OrganizationalUnitId: id, Name: required(form, "name", "Name") }));
    return "Renamed";
  }, { revalidate: [ROOT], fields: { Name: "name", DuplicateOrganizationalUnitException: "name" } });
}

export async function removeAccount(id: string) {
  return act(async () => {
    await (await organizations()).send(new RemoveAccountFromOrganizationCommand({ AccountId: id }));
    redirect(ROOT);
  });
}

export async function closeAccount(id: string) {
  return act(async () => {
    await (await organizations()).send(new CloseAccountCommand({ AccountId: id }));
    return "Closing the account";
  }, ROOT, accountPage(id));
}

/** Replace the tags of an account, OU, root or policy with the form's `key=value` lines. */
export async function saveTags(resource: string, path: string, _: ActionResult | null, form: FormData) {
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
    const client = await organizations();
    const current = (await client.send(new ListTagsForResourceCommand({ ResourceId: resource }))).Tags ?? [];
    const TagKeys = current.map((t) => t.Key!).filter((k) => !Tags.some((t) => t.Key === k));
    if (TagKeys.length) await client.send(new UntagResourceCommand({ ResourceId: resource, TagKeys }));
    if (Tags.length) await client.send(new TagResourceCommand({ ResourceId: resource, Tags }));
    return "Tags saved";
  }, { revalidate: [path], fields: { Tags: "tags", TagKeys: "tags", InvalidInputException: "tags" } });
}

export async function setServiceAccess(principal: string, on: boolean) {
  return act(async () => {
    const client = await organizations();
    if (on) await client.send(new EnableAWSServiceAccessCommand({ ServicePrincipal: principal }));
    else await client.send(new DisableAWSServiceAccessCommand({ ServicePrincipal: principal }));
    return on ? "Trusted access enabled" : "Trusted access disabled";
  }, `${ROOT}/services`);
}

export async function enableServiceAccess(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await organizations()).send(new EnableAWSServiceAccessCommand({ ServicePrincipal: required(form, "principal", "Service principal") }));
    return "Trusted access enabled";
  }, { revalidate: [`${ROOT}/services`], fields: { ServicePrincipal: "principal" } });
}

export async function registerDelegatedAdmin(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await organizations()).send(new RegisterDelegatedAdministratorCommand({ AccountId: required(form, "account", "Account"), ServicePrincipal: required(form, "principal", "Service principal") }));
    return "Delegated administrator registered";
  }, { revalidate: [`${ROOT}/services`], fields: { AccountId: "account", ServicePrincipal: "principal", AccountAlreadyRegisteredException: "account", AccountNotFoundException: "account", ConstraintViolationException: "account" } });
}

export async function deregisterDelegatedAdmin(account: string, principal: string) {
  return act(async () => {
    await (await organizations()).send(new DeregisterDelegatedAdministratorCommand({ AccountId: account, ServicePrincipal: principal }));
    return "Deregistered";
  }, `${ROOT}/services`, accountPage(account));
}

export async function inviteAccount(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const target = required(form, "target", "Account ID or email");
    await (await organizations()).send(
      new InviteAccountToOrganizationCommand({ Target: { Id: target, Type: target.includes("@") ? "EMAIL" : "ACCOUNT" }, Notes: text(form, "notes") || undefined }),
    );
    return "Invitation sent";
  }, { revalidate: [`${ROOT}/invitations`], fields: { "Target.Id": "target", Target: "target", Notes: "notes", DuplicateHandshakeException: "target", AccountNotFoundException: "target", HandshakeConstraintViolationException: "target" } });
}

export async function cancelHandshake(id: string) {
  return act(async () => {
    await (await organizations()).send(new CancelHandshakeCommand({ HandshakeId: id }));
    return "Invitation canceled";
  }, `${ROOT}/invitations`);
}

export async function attachPolicy(policy: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await organizations()).send(new AttachPolicyCommand({ PolicyId: policy, TargetId: required(form, "target", "Target") }));
    return "Attached";
  }, { revalidate: [ROOT, policyPage(policy)], fields: { ConstraintViolationException: "target", TargetId: "target", TargetNotFoundException: "target", DuplicatePolicyAttachmentException: "target" } });
}

export async function detachPolicy(policy: string, target: string) {
  return act(async () => {
    await (await organizations()).send(new DetachPolicyCommand({ PolicyId: policy, TargetId: target }));
    return "Detached";
  }, ROOT, policyPage(policy), accountPage(target));
}

/** The reason of a ConstraintViolationException, if `e` is one. */
function constraint(e: unknown): string | undefined {
  return e instanceof Error && e.name === "ConstraintViolationException" ? (e as Error & { Reason?: string }).Reason : undefined;
}
