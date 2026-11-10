import { GetEmailTemplateCommand } from "@aws-sdk/client-sesv2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Field, Page, Section, Sheet } from "@mws-dashboard/ui";
import { FlaskConical, Pencil, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ses } from "../../../lib/clients";
import { deleteTemplate, testRender, updateTemplate } from "../template-actions";

export const metadata: Metadata = { title: "Email template" };

type Props = { searchParams: Promise<{ name?: string }> };

/** The `{{variables}}` a template uses, for sample data. */
function variables(...parts: (string | undefined)[]) {
  const names = new Set<string>();
  for (const p of parts) for (const m of (p ?? "").matchAll(/\{\{\{?\s*([A-Za-z_][\w.]*)\s*\}?\}\}/g)) if (!["else", "this"].includes(m[1])) names.add(m[1].split(".")[0]);
  return [...names];
}

export default async function Template({ searchParams }: Props) {
  const { name = "" } = await searchParams;
  const back = { href: "/ses?tab=templates", label: "Email templates" };
  const data = await load(async () => (await (await ses()).send(new GetEmailTemplateCommand({ TemplateName: name }))).TemplateContent ?? {});
  if (!data.ok) {
    return (
      <Page title={name || "Email template"} icon={ICONS.email} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const t = data.value;
  const vars = variables(t.Subject, t.Text, t.Html);
  const sample = JSON.stringify(Object.fromEntries(vars.map((v) => [v, `sample ${v}`])), null, 2);
  return (
    <Page
      title={name}
      icon={ICONS.email}
      back={back}
      subtitle="Email template"
      actions={
        <>
          <Sheet title="Test template" label="Test template" icon={<FlaskConical size={16} />} testId="test-render">
            <ActionForm action={testRender.bind(null, name)} submit="Render" testId="test-render">
              <Field label="Template data" format="json" member="TemplateData">
                <textarea name="data" rows={6} className="code-editor" defaultValue={sample} />
              </Field>
            </ActionForm>
          </Sheet>
          <Sheet title="Edit template" label="Edit template" icon={<Pencil size={16} />} testId="edit-template">
            <ActionForm action={updateTemplate.bind(null, name)} submit="Save" testId="edit-template">
              <Field label="Subject" rule={{ required: true }} member="Subject">
                <input name="subject" required defaultValue={t.Subject} />
              </Field>
              <Field label="Text part" member="Text">
                <textarea name="text" rows={5} defaultValue={t.Text} />
              </Field>
              <Field label="HTML part" member="Html">
                <textarea name="html" rows={5} className="code-editor" defaultValue={t.Html} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteTemplate.bind(null, name, true)} submit="Delete template" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-template" />
        </>
      }
    >
      <Section title="Subject" plain>
        <p>{t.Subject}</p>
      </Section>
      {vars.length > 0 && (
        <Section title="Variables" count={vars.length} plain>
          <p className="muted">{vars.map((v) => `{{${v}}}`).join(", ")}</p>
        </Section>
      )}
      <Section title="Text part" plain>
        <CodeBlock value={t.Text} label="Text part" />
      </Section>
      <Section title="HTML part" plain>
        <CodeBlock value={t.Html} label="HTML part" />
      </Section>
    </Page>
  );
}
