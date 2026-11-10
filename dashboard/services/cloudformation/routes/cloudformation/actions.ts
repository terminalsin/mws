"use server";

import { CreateStackCommand, DeleteStackCommand, UpdateStackCommand } from "@aws-sdk/client-cloudformation";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { cloudformation } from "../../lib/clients";

function parameters(form: FormData) {
  return text(form, "parameters")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.includes("="))
    .map((l) => ({ ParameterKey: l.slice(0, l.indexOf("=")).trim(), ParameterValue: l.slice(l.indexOf("=") + 1).trim() }));
}

const CAPABILITIES = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"] as const;

export async function createStack(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const StackName = required(form, "name", "Stack name");
    await (await cloudformation()).send(
      new CreateStackCommand({ StackName, TemplateBody: required(form, "template", "Template"), Parameters: parameters(form), Capabilities: [...CAPABILITIES], OnFailure: (text(form, "onFailure") || "ROLLBACK") as "ROLLBACK" | "DELETE" | "DO_NOTHING" }),
    );
    redirect(`/cloudformation/stack?name=${encodeURIComponent(StackName)}`);
  });
}

export async function updateStack(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await cloudformation()).send(new UpdateStackCommand({ StackName: name, TemplateBody: required(form, "template", "Template"), Parameters: parameters(form), Capabilities: [...CAPABILITIES] }));
    return "Update started";
  }, "/cloudformation/stack");
}

export async function deleteStack(name: string) {
  return act(async () => {
    await (await cloudformation()).send(new DeleteStackCommand({ StackName: name }));
    redirect("/cloudformation");
  });
}
