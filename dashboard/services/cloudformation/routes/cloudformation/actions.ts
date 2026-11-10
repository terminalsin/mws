"use server";

import {
  CancelUpdateStackCommand,
  ContinueUpdateRollbackCommand,
  CreateChangeSetCommand,
  CreateStackCommand,
  DeleteChangeSetCommand,
  DeleteStackCommand,
  DetectStackDriftCommand,
  DetectStackResourceDriftCommand,
  ExecuteChangeSetCommand,
  GetTemplateSummaryCommand,
  ListTypesCommand,
  RollbackStackCommand,
  SetStackPolicyCommand,
  UpdateStackCommand,
  UpdateTerminationProtectionCommand,
  type Capability,
  type ChangeSetType,
  type CloudFormationClient,
  type OnFailure,
  type Parameter,
  type ResourceToImport,
} from "@aws-sdk/client-cloudformation";
import { act, collect, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { IMPORT_IDENTIFIERS } from "../../lib/cloudformation";
import { cloudformation } from "../../lib/clients";
import { parametersError, templateError } from "../../lib/repairs";

const enc = encodeURIComponent;
const lines = (form: FormData, name: string) =>
  text(form, name)
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.includes("="));

/** The parameters typed as `Key=value` lines. `previous` holds what the
 * update form showed for each of the stack's current parameters: a value
 * left as shown is sent as `UsePreviousValue`, so a `NoEcho` parameter
 * (shown as `****`) keeps its secret instead of becoming the mask. */
function parameters(form: FormData, previous: Record<string, string> = {}): Parameter[] {
  return lines(form, "parameters").map((l) => {
    const key = l.slice(0, l.indexOf("=")).trim();
    const value = l.slice(l.indexOf("=") + 1).trim();
    if (key in previous && (value === previous[key] || value === "****")) return { ParameterKey: key, UsePreviousValue: true };
    return { ParameterKey: key, ParameterValue: value };
  });
}

function tags(form: FormData) {
  return lines(form, "tags").map((l) => ({ Key: l.slice(0, l.indexOf("=")).trim(), Value: l.slice(l.indexOf("=") + 1).trim() }));
}

/** The capabilities the person acknowledged (AWS refuses IAM resources and
 * macros without them, with InsufficientCapabilities). */
const capabilities = (form: FormData) => form.getAll("capabilities").map(String) as Capability[];

const optional = (form: FormData, name: string) => text(form, name) || undefined;
const minutes = (form: FormData) => (text(form, "timeout") ? Number(text(form, "timeout")) : undefined);
const topics = (form: FormData) =>
  text(form, "notifications")
    .split(/[\s,]+/)
    .filter(Boolean);

/** Send a create or update, turning template and parameter errors into
 * issues on those fields, with repairs. */
async function deploy(client: CloudFormationClient, form: FormData, send: (template: string) => Promise<unknown>) {
  const template = required(form, "template", "Template");
  try {
    await send(template);
  } catch (e) {
    if (!(e instanceof Error) || e.name !== "ValidationError") throw e;
    const types = () =>
      collect(
        (NextToken) => client.send(new ListTypesCommand({ Visibility: "PUBLIC", Type: "RESOURCE", NextToken })),
        (r) => r.TypeSummaries,
        (r) => r.NextToken,
      ).then((all) => all.map((t) => t.TypeName!).filter(Boolean));
    // Repairs rewrite the field's value as typed (forms submit CRLF).
    const raw = (name: string) => String(form.get(name) ?? "").replace(/\r\n/g, "\n");
    throw (await templateError(e.message, raw("template"), types)) ?? parametersError(e.message, raw("template"), raw("parameters")) ?? e;
  }
}

const FIELDS = {
  StackName: "name",
  TemplateBody: "template",
  Parameters: "parameters",
  OnFailure: "onFailure",
  RoleARN: "role",
  Tags: "tags",
  TimeoutInMinutes: "timeout",
  NotificationARNs: "notifications",
  ChangeSetName: "changeSet",
  ResourcesToImport: "imports",
  StackPolicyBody: "policy",
};

const stackHref = (name: string, tab?: string) => `/cloudformation/stack?name=${enc(name)}${tab ? `&tab=${tab}` : ""}`;

export async function createStack(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const StackName = required(form, "name", "Stack name");
      const client = await cloudformation();
      await deploy(client, form, (TemplateBody) =>
        client.send(
          new CreateStackCommand({
            StackName,
            TemplateBody,
            Parameters: parameters(form),
            Capabilities: capabilities(form),
            OnFailure: (text(form, "onFailure") || "ROLLBACK") as OnFailure,
            RoleARN: optional(form, "role"),
            Tags: tags(form),
            TimeoutInMinutes: minutes(form),
            NotificationARNs: topics(form),
            EnableTerminationProtection: form.get("protect") === "on",
          }),
        ),
      );
      redirect(stackHref(StackName));
    },
    { fields: FIELDS },
  );
}

export async function updateStack(name: string, previous: Record<string, string>, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const client = await cloudformation();
      await deploy(client, form, (TemplateBody) =>
        client.send(
          new UpdateStackCommand({
            StackName: name,
            TemplateBody,
            Parameters: parameters(form, previous),
            Capabilities: capabilities(form),
            RoleARN: optional(form, "role"),
            DisableRollback: form.get("disableRollback") === "on" || undefined,
          }),
        ),
      );
      redirect(stackHref(name, "events"));
    },
    { fields: FIELDS },
  );
}

/** Lines of `LogicalId=identifier`, typed against the template's resources:
 * the type comes from the template, the identifier property from the type. */
async function importsFrom(client: CloudFormationClient, TemplateBody: string, form: FormData): Promise<ResourceToImport[]> {
  const wanted = lines(form, "imports");
  if (wanted.length === 0) throw new FieldError("imports", "Name at least one resource to import, as LogicalId=identifier", "required");
  const summary = await client.send(new GetTemplateSummaryCommand({ TemplateBody }));
  const typeOf = new Map<string, string>();
  for (const s of summary.ResourceIdentifierSummaries ?? []) for (const id of s.LogicalResourceIds ?? []) typeOf.set(id, s.ResourceType!);
  return wanted.map((l) => {
    const logical = l.slice(0, l.indexOf("=")).trim();
    const value = l.slice(l.indexOf("=") + 1).trim();
    const type = typeOf.get(logical);
    if (!type) throw new FieldError("imports", `${logical} isn't a resource of the template`, "server", { known: [...typeOf.keys()] });
    const key = IMPORT_IDENTIFIERS[type];
    if (!key) throw new FieldError("imports", `${type} can't be imported`, "server");
    return { LogicalResourceId: logical, ResourceType: type, ResourceIdentifier: { [key]: value } };
  });
}

/** Create a change set: an update of `stack`, or (with no stack bound) a
 * new stack created or imported through one. */
export async function createChangeSet(stack: string | null, previous: Record<string, string>, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const StackName = stack ?? required(form, "name", "Stack name");
      const ChangeSetName = required(form, "changeSet", "Change set name");
      const ChangeSetType = (text(form, "type") || (stack ? "UPDATE" : "CREATE")) as ChangeSetType;
      const client = await cloudformation();
      await deploy(client, form, async (TemplateBody) =>
        client.send(
          new CreateChangeSetCommand({
            StackName,
            ChangeSetName,
            ChangeSetType,
            TemplateBody,
            Description: optional(form, "description"),
            Parameters: parameters(form, ChangeSetType === "UPDATE" ? previous : {}),
            Capabilities: capabilities(form),
            RoleARN: optional(form, "role"),
            Tags: ChangeSetType === "UPDATE" ? undefined : tags(form),
            ResourcesToImport: ChangeSetType === "IMPORT" ? await importsFrom(client, TemplateBody, form) : undefined,
          }),
        ),
      );
      redirect(`/cloudformation/changeset?stack=${enc(StackName)}&name=${enc(ChangeSetName)}`);
    },
    { fields: FIELDS },
  );
}

export async function executeChangeSet(stack: string, changeSet: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await cloudformation()).send(
      new ExecuteChangeSetCommand({ StackName: stack, ChangeSetName: changeSet, DisableRollback: form.get("disableRollback") === "on" || undefined }),
    );
    redirect(stackHref(stack, "events"));
  });
}

export async function deleteChangeSet(stack: string, changeSet: string) {
  return act(async () => {
    await (await cloudformation()).send(new DeleteChangeSetCommand({ StackName: stack, ChangeSetName: changeSet }));
    redirect(stackHref(stack, "changesets"));
  });
}

/** Delete a stack. For a stack whose last delete failed, `retain` lists the
 * resources to leave behind (AWS accepts RetainResources only then). */
export async function deleteStack(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const retain = form.getAll("retain").map(String);
    await (await cloudformation()).send(new DeleteStackCommand({ StackName: name, RetainResources: retain.length ? retain : undefined }));
    redirect("/cloudformation");
  });
}

export async function cancelUpdate(name: string) {
  return act(async () => {
    await (await cloudformation()).send(new CancelUpdateStackCommand({ StackName: name }));
    return "Cancelling the update";
  }, "/cloudformation/stack");
}

export async function continueRollback(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const skip = form.getAll("skip").map(String);
    await (await cloudformation()).send(new ContinueUpdateRollbackCommand({ StackName: name, ResourcesToSkip: skip.length ? skip : undefined }));
    return "Rollback continued";
  }, "/cloudformation/stack");
}

export async function rollbackStack(name: string) {
  return act(async () => {
    await (await cloudformation()).send(new RollbackStackCommand({ StackName: name }));
    return "Rolling back";
  }, "/cloudformation/stack");
}

export async function setTerminationProtection(name: string, enable: boolean) {
  return act(async () => {
    await (await cloudformation()).send(new UpdateTerminationProtectionCommand({ StackName: name, EnableTerminationProtection: enable }));
    return enable ? "Termination protection on" : "Termination protection off";
  }, "/cloudformation/stack");
}

export async function setStackPolicy(name: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      await (await cloudformation()).send(new SetStackPolicyCommand({ StackName: name, StackPolicyBody: required(form, "policy", "Stack policy") }));
      return "Stack policy saved";
    },
    { revalidate: ["/cloudformation/stack"], fields: FIELDS },
  );
}

export async function detectDrift(name: string) {
  return act(async () => {
    const r = await (await cloudformation()).send(new DetectStackDriftCommand({ StackName: name }));
    redirect(`${stackHref(name, "drift")}&detection=${enc(r.StackDriftDetectionId!)}`);
  });
}

export async function detectResourceDrift(name: string, logicalId: string) {
  return act(async () => {
    const r = await (await cloudformation()).send(new DetectStackResourceDriftCommand({ StackName: name, LogicalResourceId: logicalId }));
    return `${logicalId}: ${(r.StackResourceDrift?.StackResourceDriftStatus ?? "").toLowerCase().replace(/_/g, " ")}`;
  }, "/cloudformation/stack");
}
