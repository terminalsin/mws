"use server";

import { CreateStackCommand, DeleteStackCommand, ListTypesCommand, UpdateStackCommand, type CloudFormationClient } from "@aws-sdk/client-cloudformation";
import { act, collect, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { cloudformation } from "../../lib/clients";
import { parametersError, templateError } from "../../lib/repairs";

function parameters(form: FormData) {
  return text(form, "parameters")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.includes("="))
    .map((l) => ({ ParameterKey: l.slice(0, l.indexOf("=")).trim(), ParameterValue: l.slice(l.indexOf("=") + 1).trim() }));
}

const CAPABILITIES = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"] as const;

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

const FIELDS = { StackName: "name", TemplateBody: "template", Parameters: "parameters", OnFailure: "onFailure" };

export async function createStack(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const StackName = required(form, "name", "Stack name");
    const client = await cloudformation();
    await deploy(client, form, (TemplateBody) =>
      client.send(
        new CreateStackCommand({ StackName, TemplateBody, Parameters: parameters(form), Capabilities: [...CAPABILITIES], OnFailure: (text(form, "onFailure") || "ROLLBACK") as "ROLLBACK" | "DELETE" | "DO_NOTHING" }),
      ),
    );
    redirect(`/cloudformation/stack?name=${encodeURIComponent(StackName)}`);
  }, { fields: FIELDS });
}

export async function updateStack(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await cloudformation();
    await deploy(client, form, (TemplateBody) => client.send(new UpdateStackCommand({ StackName: name, TemplateBody, Parameters: parameters(form), Capabilities: [...CAPABILITIES] })));
    return "Update started";
  }, { revalidate: ["/cloudformation/stack"], fields: FIELDS });
}

export async function deleteStack(name: string) {
  return act(async () => {
    await (await cloudformation()).send(new DeleteStackCommand({ StackName: name }));
    redirect("/cloudformation");
  });
}
