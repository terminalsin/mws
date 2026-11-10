"use server";

import { CreateOpsItemCommand, DeleteOpsItemCommand, UpdateOpsItemCommand, type OpsItemStatus } from "@aws-sdk/client-ssm";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ssm } from "../../../lib/clients";

const FIELDS = { Title: "title", Source: "source", Description: "description", Priority: "priority", Severity: "severity", Category: "category", OpsItemType: "type", OpsItemInvalidParameterException: "title" };

export async function createOpsItem(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const priority = Number(text(form, "priority") || 0);
    const out = await (await ssm()).send(
      new CreateOpsItemCommand({
        Title: required(form, "title", "Title"),
        Source: required(form, "source", "Source"),
        Description: required(form, "description", "Description"),
        Priority: priority || undefined,
        Severity: text(form, "severity") || undefined,
        Category: text(form, "category") || undefined,
        OpsItemType: text(form, "type") || undefined,
      }),
    );
    redirect(`/ssm/opsitem?id=${out.OpsItemId}`);
  }, { fields: FIELDS });
}

export async function setStatus(id: string, status: OpsItemStatus) {
  return act(async () => {
    await (await ssm()).send(new UpdateOpsItemCommand({ OpsItemId: id, Status: status }));
    return `Status: ${status}`;
  }, "/ssm/opsitem", "/ssm/opsitems");
}

export async function updateOpsItem(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const priority = Number(text(form, "priority") || 0);
    await (await ssm()).send(
      new UpdateOpsItemCommand({
        OpsItemId: id,
        Title: required(form, "title", "Title"),
        Description: required(form, "description", "Description"),
        Priority: priority || undefined,
        Severity: text(form, "severity") || undefined,
        Category: text(form, "category") || undefined,
      }),
    );
    return "Saved";
  }, { revalidate: ["/ssm/opsitem", "/ssm/opsitems"], fields: FIELDS });
}

export async function deleteOpsItem(id: string) {
  return act(async () => {
    await (await ssm()).send(new DeleteOpsItemCommand({ OpsItemId: id }));
    redirect("/ssm/opsitems");
  });
}
