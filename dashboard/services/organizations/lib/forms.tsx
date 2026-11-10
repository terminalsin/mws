"use client";

// Organizations' create forms: a policy starts from a guardrail template; a
// new account's owner email follows its name, plus-addressed on the
// management account's address, until it is typed.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateAccount, CreatePolicy } from "@mws-dashboard/ui/model/organizations";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { Braces } from "lucide-react";
import { useState } from "react";

import { ORG_POLICY_PRESETS, emailTag, type OrgPolicyPreset } from "./presets";

export function OrgPolicyFields({ type, example, region, org, taken, content }: { type: string; example: string; region: string; org: string; taken: string[]; content: Rule }) {
  const presets = ORG_POLICY_PRESETS[type] ?? [];
  const custom: OrgPolicyPreset = { id: "custom", label: "Custom", icon: "", name: "", description: "", content: () => JSON.parse(example) };
  const [preset, setPreset] = useState<OrgPolicyPreset>(presets[0] ?? custom);
  const items = [...presets.map((p) => ({ ...p, title: p.description, added: taken.includes(p.name) })), { ...custom, icon: <Braces size={24} aria-hidden /> }];
  return (
    <>
      {presets.length > 0 && <PresetGallery presets={items} chosen={preset.id} choose={(p) => setPreset([...presets, custom].find((x) => x.id === p.id)!)} label="Template" size={26} />}
      <div key={preset.id} className="preset-fields">
        <FieldShell label="Name" rule={CreatePolicy.Name} taken={taken} generate="name" unique>
          <input name="name" required defaultValue={preset.name ? freeName(preset.name, taken) : undefined} autoFocus={!preset.name} />
        </FieldShell>
        <FieldShell label="Policy" rule={content}>
          <textarea name="content" rows={12} className="code-editor" spellCheck={false} defaultValue={preset.id === "custom" ? example : JSON.stringify(preset.content(region, org), null, 2)} />
        </FieldShell>
        <MoreFields>
          <FieldShell label="Description" rule={{ ...CreatePolicy.Description, required: false }}>
            <input name="description" defaultValue={preset.description} />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}

export function AccountFields({ owner, emails }: { owner?: string; emails: string[] }) {
  const [name, setName] = useState("");
  const [typed, setTyped] = useState<string | null>(null);
  const [local, domain] = (owner ?? "").split("@");
  const tag = emailTag(name);
  const suggested = domain && tag ? freeName(`${local.split("+")[0]}+${tag}`, emails.map((e) => e.split("@")[0])) + `@${domain}` : "";
  return (
    <>
      <FieldShell label="Account name" rule={CreateAccount.AccountName} generate="name">
        <input name="name" required autoFocus value={name} onChange={(e) => setName(e.target.value)} />
      </FieldShell>
      <FieldShell label="Email address of the account's owner" rule={CreateAccount.Email} format="email" taken={emails} unique>
        <input name="email" type="email" required value={typed ?? suggested} onChange={(e) => setTyped(e.target.value)} placeholder={domain ? `${local}+name@${domain}` : undefined} />
      </FieldShell>
    </>
  );
}
