"use server";

import { CreateEmailTemplateCommand, DeleteEmailTemplateCommand, TestRenderEmailTemplateCommand, UpdateEmailTemplateCommand } from "@aws-sdk/client-sesv2";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ses, templateHref } from "../../lib/clients";

const content = (form: FormData) => ({ Subject: required(form, "subject", "Subject"), Text: text(form, "text") || undefined, Html: text(form, "html") || undefined });
const FIELDS = { TemplateName: "name", AlreadyExistsException: "name", Subject: "subject", Text: "text", Html: "html", TemplateContent: "subject" };

export async function createTemplate(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    await (await ses()).send(new CreateEmailTemplateCommand({ TemplateName: name, TemplateContent: content(form) }));
    redirect(templateHref(name));
  }, { fields: FIELDS });
}

export async function updateTemplate(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ses()).send(new UpdateEmailTemplateCommand({ TemplateName: name, TemplateContent: content(form) }));
    return "Template saved";
  }, { revalidate: ["/ses/template"], fields: FIELDS });
}

export async function deleteTemplate(name: string, back?: boolean) {
  return act(async () => {
    await (await ses()).send(new DeleteEmailTemplateCommand({ TemplateName: name }));
    if (back) redirect("/ses?tab=templates");
    return `Deleted ${name}`;
  }, "/ses");
}

/** Render with sample data; the rendered MIME comes back in the result. */
export async function testRender(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ses()).send(new TestRenderEmailTemplateCommand({ TemplateName: name, TemplateData: text(form, "data") || "{}" }));
    return { ok: true, message: "Rendered", detail: out.RenderedTemplate };
  }, { fields: { TemplateData: "data", BadRequestException: "data" } });
}
