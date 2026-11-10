"use client";

import { ActionForm, Field } from "@mws-dashboard/ui";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { useMemo, useState } from "react";

import { ENGINE_PRESETS, type EnginePreset } from "../../lib/presets";
import { DATABASE_NAME, RETENTION, family, identifier, password, STORAGE, username } from "../../lib/rules";
import { createDatabase } from "./actions";

const DEFAULT_USER = { postgres: "postgres", mysql: "admin" };
const PREFERRED_CLASS = ["db.t4g.micro", "db.t4g.medium", "db.t3.micro", "db.t3.medium"];

const ID = identifier(63);
const USER = { postgres: username("postgres"), mysql: username("mysql") };
const PASSWORD = { postgres: password("postgres"), mysql: password("mysql") };

/** The create sheet's form. It opens on the engines' logos: picking one
 * names the database, picks the smallest class RDS offers that engine and
 * the engine's usual user; everything else waits under More. */
export function CreateDatabaseForm({ classes, versions, taken, inUse = [] }: { classes: Record<string, string[]>; versions: Record<string, string[]>; taken: string[]; inUse?: string[] }) {
  const [preset, setPreset] = useState<EnginePreset>(ENGINE_PRESETS[0]);
  const engine = preset.id;
  const f = family(engine);
  const aurora = engine.startsWith("aurora");
  const offered = useMemo(() => classes[engine] ?? [], [classes, engine]);
  const classRule = useMemo(() => (offered.length ? { required: true, enum: offered } : { required: true }), [offered]);
  const pick = (list: string[]) => PREFERRED_CLASS.find((c) => list.includes(c)) ?? list[0] ?? "db.t4g.micro";

  return (
    <ActionForm action={createDatabase} submit="Create database" testId="create-database">
      <PresetGallery presets={ENGINE_PRESETS.map((p) => ({ ...p, added: inUse.includes(p.id) }))} chosen={engine} choose={setPreset} label="Engine" />
      <input type="hidden" name="engine" value={engine} />
      {/* Fields remount per engine, so each starts from that engine's defaults. */}
      <div key={engine} className="preset-fields">
        <div className="form-row">
          <Field label="DB identifier" rule={ID} taken={taken} unique>
            <input name="id" required spellCheck={false} defaultValue={freeName(engine, taken)} />
          </Field>
          <Field label="Instance class" rule={classRule}>
            <input name="class" defaultValue={pick(offered)} list="db-classes" spellCheck={false} />
          </Field>
        </div>
        <datalist id="db-classes">
          {offered.map((c) => (
            <option key={c} value={c} />
          ))}
        </datalist>
        <div className="form-row">
          <Field label="Master username" rule={USER[f]}>
            <input name="username" defaultValue={DEFAULT_USER[f]} spellCheck={false} />
          </Field>
          <Field label="Master password" rule={PASSWORD[f]}>
            <input name="password" type="password" autoComplete="new-password" />
          </Field>
        </div>
        <MoreFields>
          <div className="form-row">
            <Field label="Engine version">
              <select name="version" defaultValue="">
                <option value="">Default</option>
                {(versions[engine] ?? []).map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </Field>
            {!aurora && (
              <Field label="Storage (GiB)" rule={STORAGE}>
                <input name="storage" type="number" defaultValue={20} />
              </Field>
            )}
          </div>
          <div className="form-row">
            <Field label="Initial database name" rule={DATABASE_NAME[f]}>
              <input name="dbName" spellCheck={false} placeholder="optional" />
            </Field>
            <Field label="Backup retention (days)" rule={RETENTION}>
              <input name="retention" type="number" defaultValue={1} />
            </Field>
          </div>
          <div className="form-row">
            {!aurora && (
              <label className="check">
                <input type="checkbox" name="multiAz" /> Multi-AZ
              </label>
            )}
            {!aurora && (
              <label className="check">
                <input type="checkbox" name="public" /> Publicly accessible
              </label>
            )}
            <label className="check">
              <input type="checkbox" name="encrypted" defaultChecked /> Encryption
            </label>
            <label className="check">
              <input type="checkbox" name="deletionProtection" /> Deletion protection
            </label>
          </div>
        </MoreFields>
      </div>
    </ActionForm>
  );
}
