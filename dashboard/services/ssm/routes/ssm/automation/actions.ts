"use server";

import { SendAutomationSignalCommand, StartAutomationExecutionCommand, StopAutomationExecutionCommand, type SignalType } from "@aws-sdk/client-ssm";
import { act, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ssm } from "../../../lib/clients";

/** Start a runbook with the parameters its form filled (`param:<name>`; a
 * StringList or MapList takes one value a line). */
export async function startAutomation(document: string, listParams: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Parameters: Record<string, string[]> = {};
    for (const [k, v] of form.entries()) {
      if (!k.startsWith("param:") || typeof v !== "string" || v.trim() === "") continue;
      const name = k.slice(6);
      Parameters[name] = listParams.includes(name) ? v.split("\n").map((l) => l.trim()).filter(Boolean) : [v];
    }
    const out = await (await ssm()).send(
      new StartAutomationExecutionCommand({
        DocumentName: document,
        DocumentVersion: text(form, "version") || undefined,
        Mode: text(form, "mode") === "Interactive" ? "Interactive" : "Auto",
        Parameters: Object.keys(Parameters).length ? Parameters : undefined,
      }),
    );
    redirect(`/ssm/automation/execution?id=${out.AutomationExecutionId}`);
  }, {
    fields: { DocumentVersion: "version", InvalidAutomationExecutionParametersException: "params", AutomationDefinitionVersionNotFoundException: "version" },
  });
}

/** Approve, reject or resume a waiting step (`aws:approve`, `aws:pause`), or
 * step an interactive run. */
export async function signal(id: string, type: SignalType, step: string | undefined, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const comment = text(form, "comment");
    const Payload: Record<string, string[]> = {};
    if (comment) Payload.Comment = [comment];
    if (step) Payload.StepName = [step];
    await (await ssm()).send(new SendAutomationSignalCommand({ AutomationExecutionId: id, SignalType: type, Payload: Object.keys(Payload).length ? Payload : undefined }));
    return `${type} sent`;
  }, { revalidate: ["/ssm/automation/execution"], fields: { InvalidAutomationSignalException: "comment", AutomationStepNotFoundException: "comment" } });
}

export async function stopAutomation(id: string, type: "Cancel" | "Complete") {
  return act(async () => {
    await (await ssm()).send(new StopAutomationExecutionCommand({ AutomationExecutionId: id, Type: type }));
    return type === "Cancel" ? "Cancelling" : "Completing";
  }, "/ssm/automation/execution", "/ssm/automation");
}

