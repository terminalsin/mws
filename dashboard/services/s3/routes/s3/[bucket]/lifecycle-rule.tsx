"use client";

import { ActionForm, Field } from "@mws-dashboard/ui";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { CloudOff, History, Timer } from "lucide-react";
import { useState, type ReactNode } from "react";

import { LIFECYCLE_PRESETS, type LifecyclePreset } from "../../../lib/presets";
import { addLifecycleRule } from "../actions";

const STORAGE_CLASSES = ["STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"];
const DAYS = { type: "integer", min: 1 } as const;

const LUCIDE: Record<string, ReactNode> = {
  "lucide:timer": <Timer size={26} strokeWidth={1.5} aria-hidden />,
  "lucide:history": <History size={26} strokeWidth={1.5} aria-hidden />,
  "lucide:upload-x": <CloudOff size={26} strokeWidth={1.5} aria-hidden />,
};

/** The create-rule form: it opens on the rules people usually want. Each
 * fills the days it needs; the other actions wait under More. */
export function LifecycleRuleForm({ bucket, taken }: { bucket: string; taken: string[] }) {
  const [p, setP] = useState<LifecyclePreset>(LIFECYCLE_PRESETS[0]);
  const transition = (
    <div className="form-row">
      <Field label="Transition after (days)" rule={DAYS}>
        <input name="transition" type="number" min={1} defaultValue={p.transition} />
      </Field>
      <Field label="To storage class">
        <select name="storageClass" defaultValue={p.storageClass ?? "STANDARD_IA"}>
          {STORAGE_CLASSES.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
      </Field>
    </div>
  );
  const expire = (
    <Field label="Expire current versions after (days)" rule={DAYS}>
      <input name="expire" type="number" min={1} defaultValue={p.expire} />
    </Field>
  );
  const noncurrent = (
    <Field label="Expire noncurrent versions after (days)" rule={DAYS}>
      <input name="noncurrent" type="number" min={1} defaultValue={p.noncurrent} />
    </Field>
  );
  const abort = (
    <Field label="Abort incomplete uploads after (days)" rule={DAYS}>
      <input name="abort" type="number" min={1} defaultValue={p.abort} />
    </Field>
  );
  return (
    <ActionForm action={addLifecycleRule.bind(null, bucket)} submit="Create rule" testId="create-lifecycle-rule">
      <PresetGallery presets={LIFECYCLE_PRESETS.map((x) => ({ ...x, icon: LUCIDE[x.icon] ?? x.icon }))} chosen={p.id} choose={(x) => setP(LIFECYCLE_PRESETS.find((y) => y.id === x.id)!)} label="Rule" />
      <div key={p.id} className="preset-fields">
        <div className="form-row">
          <Field label="Rule name" rule={{ maxLength: 255, generate: "name" }} taken={taken} unique>
            <input name="id" required defaultValue={freeName(p.name, taken)} />
          </Field>
          <Field label="Prefix" hint="Empty applies to the whole bucket">
            <input name="prefix" placeholder="logs/" defaultValue={p.prefix} />
          </Field>
        </div>
        {p.transition != null && transition}
        {p.expire != null && expire}
        {p.noncurrent != null && noncurrent}
        {p.abort != null && abort}
        <MoreFields>
          {p.transition == null && transition}
          {p.expire == null && expire}
          {p.noncurrent == null && noncurrent}
          {p.abort == null && abort}
        </MoreFields>
      </div>
    </ActionForm>
  );
}
