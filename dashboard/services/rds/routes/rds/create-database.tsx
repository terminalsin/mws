"use client";

import { ActionForm, Field } from "@mws-dashboard/ui";
import { setControlValue } from "@mws-dashboard/ui/fields";
import { useMemo, useRef, useState } from "react";

import { ENGINES, family, identifier, password, STORAGE, username } from "../../lib/rules";
import { createDatabase } from "./actions";

const DEFAULT_USER = { postgres: "postgres", mysql: "admin" };
const PREFERRED_CLASS = ["db.t4g.micro", "db.t4g.medium", "db.t3.micro", "db.t3.medium"];

const ID = identifier(63);
const USER = { postgres: username("postgres"), mysql: username("mysql") };
const PASSWORD = { postgres: password("postgres"), mysql: password("mysql") };

/** The create sheet's form: the rules follow the engine (name and password
 * limits, the classes RDS offers it), and untouched defaults move with it. */
export function CreateDatabaseForm({ classes, taken }: { classes: Record<string, string[]>; taken: string[] }) {
  const [engine, setEngine] = useState("postgres");
  const f = family(engine);
  const aurora = engine.startsWith("aurora");
  const offered = useMemo(() => classes[engine] ?? [], [classes, engine]);
  const classRule = useMemo(() => (offered.length ? { required: true, enum: offered } : { required: true }), [offered]);
  const pick = (list: string[]) => PREFERRED_CLASS.find((c) => list.includes(c)) ?? list[0] ?? "db.t4g.micro";
  const user = useRef<HTMLInputElement>(null);
  const cls = useRef<HTMLInputElement>(null);
  // What the person typed stays; what the form filled in follows the engine.
  const typed = useRef({ user: false, cls: false });
  const filling = useRef(false);
  const fill = (el: HTMLInputElement, value: string) => {
    filling.current = true;
    setControlValue(el, value);
    filling.current = false;
  };

  const change = (next: string) => {
    const from = family(engine);
    setEngine(next);
    if (user.current && !typed.current.user && user.current.value === DEFAULT_USER[from]) fill(user.current, DEFAULT_USER[family(next)]);
    const list = classes[next] ?? [];
    if (cls.current && !typed.current.cls && list.length && !list.includes(cls.current.value)) fill(cls.current, pick(list));
  };

  return (
    <ActionForm action={createDatabase} submit="Create database" testId="create-database">
      <Field label="Engine">
        <select name="engine" value={engine} onChange={(e) => change(e.target.value)}>
          {ENGINES.map((e) => (
            <option key={e.value} value={e.value}>
              {e.label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="DB identifier" rule={ID} taken={taken} unique>
        <input name="id" required autoFocus spellCheck={false} />
      </Field>
      <div className="form-row">
        <Field label="Master username" rule={USER[f]}>
          <input ref={user} name="username" defaultValue={DEFAULT_USER.postgres} spellCheck={false} onInput={() => (typed.current.user ||= !filling.current)} />
        </Field>
        <Field label="Master password" rule={PASSWORD[f]}>
          <input name="password" type="password" autoComplete="new-password" />
        </Field>
      </div>
      <div className="form-row">
        <Field label="Instance class" rule={classRule}>
          <input ref={cls} name="class" defaultValue={pick(classes.postgres ?? [])} list="db-classes" spellCheck={false} onInput={() => (typed.current.cls ||= !filling.current)} />
        </Field>
        {!aurora && (
          <Field label="Storage (GiB)" rule={STORAGE}>
            <input name="storage" type="number" defaultValue={20} />
          </Field>
        )}
      </div>
      <datalist id="db-classes">
        {offered.map((c) => (
          <option key={c} value={c} />
        ))}
      </datalist>
      {!aurora && (
        <label className="check">
          <input type="checkbox" name="multiAz" /> Multi-AZ
        </label>
      )}
    </ActionForm>
  );
}
