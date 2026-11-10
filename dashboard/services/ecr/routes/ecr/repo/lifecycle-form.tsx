"use client";

import { ActionForm, Field, type ActionResult } from "@mws-dashboard/ui";
import { PresetGallery } from "@mws-dashboard/ui/presets";
import { CalendarClock, Eraser, GitPullRequest, Layers, Sparkles } from "lucide-react";
import { useState, type ReactNode } from "react";

import { LIFECYCLE_PRESETS } from "../../../lib/presets";

const ICON: Record<string, ReactNode> = {
  tidy: <Sparkles size={26} strokeWidth={1.5} aria-hidden />,
  untagged: <Eraser size={26} strokeWidth={1.5} aria-hidden />,
  "keep-last": <Layers size={26} strokeWidth={1.5} aria-hidden />,
  dev: <GitPullRequest size={26} strokeWidth={1.5} aria-hidden />,
  current: <CalendarClock size={26} strokeWidth={1.5} aria-hidden />,
};

const pretty = (v: object | string) => (typeof v === "string" ? JSON.stringify(JSON.parse(v), null, 2) : JSON.stringify(v, null, 2));

/** The lifecycle policy editor, over tiles of common policies: one click
 * fills the JSON, which stays editable. */
export function LifecycleForm({
  action,
  current,
  submit,
  testId,
  hint,
}: {
  action: (prev: ActionResult | null, form: FormData) => Promise<ActionResult>;
  current?: string;
  submit: string;
  testId: string;
  hint: string;
}) {
  const presets = [...(current ? [{ id: "current", label: "Current", title: "The saved policy", policy: JSON.parse(current) as object }] : []), ...LIFECYCLE_PRESETS];
  const [chosen, setChosen] = useState(presets[0]);
  return (
    <ActionForm action={action} submit={submit} testId={testId}>
      <PresetGallery presets={presets.map((p) => ({ id: p.id, label: p.label, title: p.title, icon: ICON[p.id] }))} chosen={chosen.id} choose={(p) => setChosen(presets.find((x) => x.id === p.id)!)} label="Policy" testId={`${testId}-preset`} />
      <Field label="Policy JSON" format="json" hint={hint}>
        <textarea key={chosen.id} name="policy" rows={14} className="code-editor" spellCheck={false} defaultValue={pretty(chosen.policy)} />
      </Field>
    </ActionForm>
  );
}
