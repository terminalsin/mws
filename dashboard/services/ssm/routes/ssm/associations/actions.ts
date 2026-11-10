"use server";

import { CreateAssociationCommand, DeleteAssociationCommand, StartAssociationsOnceCommand, UpdateAssociationCommand } from "@aws-sdk/client-ssm";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ssm } from "../../../lib/clients";
import { parseParameters, parseTargets } from "../../../lib/status";

const FIELDS = {
  Name: "document",
  InvalidDocument: "document",
  AssociationName: "name",
  AssociationAlreadyExists: "name",
  Targets: "targets",
  InvalidTarget: "targets",
  ScheduleExpression: "schedule",
  InvalidSchedule: "schedule",
  Parameters: "parameters",
  InvalidParameters: "parameters",
  MaxConcurrency: "maxConcurrency",
  MaxErrors: "maxErrors",
  ComplianceSeverity: "severity",
};

export async function createAssociation(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const targets = required(form, "targets", "Targets");
    const out = await (await ssm()).send(
      new CreateAssociationCommand({
        Name: required(form, "document", "Document"),
        AssociationName: text(form, "name") || undefined,
        Targets: parseTargets(targets),
        ScheduleExpression: text(form, "schedule") || undefined,
        Parameters: text(form, "parameters") ? parseParameters(text(form, "parameters")) : undefined,
        MaxConcurrency: text(form, "maxConcurrency") || undefined,
        MaxErrors: text(form, "maxErrors") || undefined,
        ComplianceSeverity: (text(form, "severity") || undefined) as "HIGH" | undefined,
        ApplyOnlyAtCronInterval: text(form, "cronOnly") === "on",
      }),
    );
    redirect(`/ssm/association?id=${out.AssociationDescription!.AssociationId}`);
  }, { fields: FIELDS });
}

export async function updateAssociation(id: string, version: string | undefined, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const targets = text(form, "targets");
    if (!targets) throw new FieldError("targets", "Targets are required", "required");
    const out = await (await ssm()).send(
      new UpdateAssociationCommand({
        AssociationId: id,
        AssociationVersion: version,
        AssociationName: text(form, "name") || undefined,
        Targets: parseTargets(targets),
        ScheduleExpression: text(form, "schedule") || undefined,
        Parameters: parseParameters(text(form, "parameters")),
        MaxConcurrency: text(form, "maxConcurrency") || undefined,
        MaxErrors: text(form, "maxErrors") || undefined,
        ComplianceSeverity: (text(form, "severity") || undefined) as "HIGH" | undefined,
      }),
    );
    return `Version ${out.AssociationDescription?.AssociationVersion} saved`;
  }, { revalidate: ["/ssm/association", "/ssm/associations"], fields: { ...FIELDS, InvalidAssociationVersion: "name" } });
}

export async function applyNow(id: string) {
  return act(async () => {
    await (await ssm()).send(new StartAssociationsOnceCommand({ AssociationIds: [id] }));
    return "Applying";
  }, "/ssm/association", "/ssm/associations");
}

export async function deleteAssociation(id: string, leave: boolean) {
  return act(async () => {
    await (await ssm()).send(new DeleteAssociationCommand({ AssociationId: id }));
    if (leave) redirect("/ssm/associations");
    return "Deleted";
  }, "/ssm/associations");
}
