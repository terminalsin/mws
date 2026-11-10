"use client";

import { ActionForm, Field, type FormAction } from "@mws-dashboard/ui";
import { PresetGallery } from "@mws-dashboard/ui/presets";
import { useState, type ReactNode } from "react";

export interface Template {
  id: string;
  label: string;
  title: string;
  icon: string | ReactNode;
  /** The JSON the template fills in. */
  text: string;
}

/** A JSON editor over tiles of common documents (policies, CORS rules): one
 * click fills the editor, which stays editable. The current document, when
 * there is one, is the first tile. */
export function TemplateForm({
  action,
  testId,
  name,
  label,
  hint,
  format,
  templates,
}: {
  action: FormAction;
  testId: string;
  name: string;
  label: string;
  hint?: string;
  format: "json" | "policy";
  templates: Template[];
}) {
  const [chosen, setChosen] = useState(templates[0]);
  return (
    <ActionForm action={action} submit="Save" testId={testId}>
      <PresetGallery presets={templates} chosen={chosen.id} choose={setChosen} label="Template" testId={`${testId}-preset`} />
      <Field label={label} hint={hint} format={format}>
        <textarea key={chosen.id} name={name} rows={14} className="code-editor" spellCheck={false} defaultValue={chosen.text} />
      </Field>
    </ActionForm>
  );
}
