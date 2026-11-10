"use client";

import { ActionForm, Field } from "@mws-dashboard/ui";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { Atom, Fingerprint, Handshake, Import, Lock, Signature, FileLock } from "lucide-react";
import { useState, type ReactNode } from "react";

import { KEY_PRESETS, type KeyPreset } from "../../lib/presets";
import { ALIAS, DESCRIPTION, KEY_POLICY, ROTATION_DAYS, TAGS } from "../../lib/rules";
import { SPECS_FOR } from "../../lib/specs";
import { createKey } from "./actions";

const ICON: Record<string, ReactNode> = {
  encrypt: <Lock size={26} strokeWidth={1.5} aria-hidden />,
  sign: <Signature size={26} strokeWidth={1.5} aria-hidden />,
  mac: <Fingerprint size={26} strokeWidth={1.5} aria-hidden />,
  rsa: <FileLock size={26} strokeWidth={1.5} aria-hidden />,
  agreement: <Handshake size={26} strokeWidth={1.5} aria-hidden />,
  pq: <Atom size={26} strokeWidth={1.5} aria-hidden />,
  import: <Import size={26} strokeWidth={1.5} aria-hidden />,
};

/** The create sheet's form: it opens on what the key is for. A symmetric
 * encryption key needs one click; the rest fold under More. */
export function CreateKeyForm({ taken }: { taken: string[] }) {
  const [preset, setPreset] = useState<KeyPreset>(KEY_PRESETS[0]);
  // Symmetric keys have one spec; RSA encryption offers its key sizes; the
  // other usages every spec KMS allows them.
  const all = SPECS_FOR[preset.usage] ?? [];
  const specs = preset.spec === "SYMMETRIC_DEFAULT" ? [preset.spec] : preset.id === "rsa" ? all.filter((s) => s.startsWith("RSA")) : all;
  const rotates = preset.spec === "SYMMETRIC_DEFAULT" && preset.origin === "AWS_KMS";
  return (
    <ActionForm action={createKey} submit="Create" testId="create-key">
      <PresetGallery
        presets={KEY_PRESETS.map((p) => ({ id: p.id, label: p.label, title: p.title, icon: ICON[p.id] }))}
        chosen={preset.id}
        choose={(p) => setPreset(KEY_PRESETS.find((k) => k.id === p.id)!)}
        label="Key type"
      />
      <input type="hidden" name="usage" value={preset.usage} />
      <input type="hidden" name="origin" value={preset.origin} />
      {/* Fields remount per preset, so each starts from that preset's values. */}
      <div key={preset.id} className="preset-fields">
        <div className="form-row">
          <Field label="Alias" rule={ALIAS} taken={taken} unique>
            <input name="alias" placeholder="alias/app-data" defaultValue={freeName(preset.alias, taken)} />
          </Field>
          {specs.length > 1 ? (
            <Field label="Key spec" member="KeySpec">
              <select name="spec" defaultValue={preset.spec}>
                {specs.map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </Field>
          ) : (
            <input type="hidden" name="spec" value={preset.spec} />
          )}
        </div>
        {rotates && (
          <label className="check">
            <input type="checkbox" name="rotation" defaultChecked /> Automatic rotation
          </label>
        )}
        <MoreFields>
          <Field label="Description" rule={DESCRIPTION}>
            <input name="description" />
          </Field>
          {rotates && (
            <Field label="Rotation period (days)" rule={ROTATION_DAYS} member="RotationPeriodInDays">
              <input name="rotationDays" type="number" placeholder="365" />
            </Field>
          )}
          <label className="check">
            <input type="checkbox" name="multiRegion" /> Multi-Region
          </label>
          <Field label="Tags" rule={TAGS}>
            <textarea name="tags" rows={2} placeholder="team=payments" />
          </Field>
          <Field label="Key policy" rule={KEY_POLICY}>
            <textarea name="policy" rows={8} placeholder="Default: the account root may use and manage the key" className="code-editor" spellCheck={false} />
          </Field>
        </MoreFields>
      </div>
    </ActionForm>
  );
}
