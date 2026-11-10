"use client";

// Identity Center's create forms: a permission set starts from AWS's
// predefined ones (the policy, name and session length filled in); a new
// user's username follows their name until it is typed.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateUser } from "@mws-dashboard/ui/model/identitystore";
import { CreatePermissionSet } from "@mws-dashboard/ui/model/sso-admin";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { useState } from "react";

import { POLICIES, SET_PRESETS, type SetPreset } from "./policies";

const HOURS: Rule = { type: "number", min: 1, max: 12 };

export function PermissionSetFields({ rule, taken }: { rule: Rule; taken: string[] }) {
  // Read only is the safe default.
  const [preset, setPreset] = useState<SetPreset>(SET_PRESETS[2]);
  const custom = !preset.policy;
  const items = SET_PRESETS.map((p) => ({ ...p, title: p.description ?? p.label, added: taken.includes(p.id) }));
  return (
    <>
      <PresetGallery presets={items} chosen={preset.id} choose={setPreset} label="Permission set" size={26} />
      <div key={preset.id} className="preset-fields">
        <FieldShell label="Name" rule={rule} member="Name" taken={taken} unique>
          <input name="name" required defaultValue={custom ? undefined : freeName(preset.id, taken)} autoFocus={custom} />
        </FieldShell>
        {custom ? (
          <FieldShell label="AWS managed policy">
            <select name="policy" defaultValue="">
              <option value="">None</option>
              {POLICIES.map((p) => (
                <option key={p} value={p}>
                  {p.split("/").pop()}
                </option>
              ))}
            </select>
          </FieldShell>
        ) : (
          <input type="hidden" name="policy" value={preset.policy} />
        )}
        <MoreFields open={custom}>
          <FieldShell label="Description" rule={CreatePermissionSet.Description} member="Description">
            <input name="description" defaultValue={preset.description} />
          </FieldShell>
          <FieldShell label="Session duration (hours)" rule={HOURS}>
            <input name="hours" type="number" min={1} max={12} defaultValue={preset.hours} />
          </FieldShell>
          <FieldShell label="Relay state" rule={CreatePermissionSet.RelayState} member="RelayState" format="url">
            <input name="relay" placeholder="https://console.aws.amazon.com/s3" />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}

const slug = (given: string, family: string) =>
  [given, family]
    .map((s) => s.trim().toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/\s+/g, "-"))
    .filter(Boolean)
    .join(".");

export function UserFields({ rule, taken }: { rule: Rule; taken: string[] }) {
  const [given, setGiven] = useState("");
  const [family, setFamily] = useState("");
  const [typed, setTyped] = useState<string | null>(null);
  const suggested = slug(given, family);
  const username = typed ?? (suggested ? freeName(suggested, taken) : "");
  return (
    <>
      <div className="form-row">
        <FieldShell label="First name" rule={CreateUser.Name.fields?.GivenName} member="Name.GivenName">
          <input name="given" required autoFocus value={given} onChange={(e) => setGiven(e.target.value)} />
        </FieldShell>
        <FieldShell label="Last name" rule={CreateUser.Name.fields?.FamilyName} member="Name.FamilyName">
          <input name="family" required value={family} onChange={(e) => setFamily(e.target.value)} />
        </FieldShell>
      </div>
      <FieldShell label="Email address" rule={CreateUser.Emails.item?.fields?.Value} member="Emails.Value" format="email">
        <input name="email" type="email" />
      </FieldShell>
      <FieldShell label="Username" rule={rule} member="UserName" taken={taken} unique>
        <input name="username" required value={username} onChange={(e) => setTyped(e.target.value)} />
      </FieldShell>
    </>
  );
}
