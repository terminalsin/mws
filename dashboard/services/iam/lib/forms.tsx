"use client";

// IAM's create forms open on tiles: a role starts from who trusts it (and
// attaches the managed policy that kind of role usually needs), a policy
// from what it allows.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateOpenIDConnectProvider } from "@mws-dashboard/ui/model/iam";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { COMMON_POLICIES, OIDC_PRESETS, POLICY_PRESETS, ROLE_PRESETS, managedArn, policyJson, trustJson, type OidcPreset, type PolicyPreset, type RolePreset } from "./presets";
import { RULES, SERVICE_PRINCIPALS } from "./rules";

export function RoleFields({ taken, account }: { taken: string[]; account: string | null }) {
  const [preset, setPreset] = useState<RolePreset>(ROLE_PRESETS[0]);
  const custom = preset.trust === "custom";
  const trust = preset.trust === "account" && account ? trustJson(account) : undefined;
  const policy = preset.attach?.split("/").pop();
  return (
    <>
      <PresetGallery presets={ROLE_PRESETS.map((p) => ({ ...p, title: p.service ?? p.label }))} chosen={preset.id} choose={setPreset} label="Trusted entity" size={26} />
      <div key={preset.id} className="preset-fields">
        <FieldShell label="Name" rule={RULES.roleName} taken={taken} unique>
          <input name="name" required defaultValue={preset.name ? freeName(preset.name, taken) : undefined} autoFocus={custom} />
        </FieldShell>
        {!preset.trust && (
          <FieldShell label="Trusted service" rule={RULES.service}>
            <input name="service" defaultValue={preset.service} list="principals" />
          </FieldShell>
        )}
        <datalist id="principals">
          {SERVICE_PRINCIPALS.map((p) => (
            <option key={p} value={p} />
          ))}
        </datalist>
        {policy && (
          <label className="check" title={preset.attach}>
            <input type="checkbox" name="attach" value={preset.attach} defaultChecked /> Attach <code>{policy}</code>
          </label>
        )}
        {custom || trust ? (
          <FieldShell label="Trust policy" rule={{ ...RULES.trust, required: true }}>
            <textarea name="trust" rows={10} className="code-editor" spellCheck={false} defaultValue={trust} placeholder='{"Version": "2012-10-17", "Statement": [...]}' />
          </FieldShell>
        ) : null}
        <MoreFields>
          <FieldShell label="Description" rule={RULES.roleDescription}>
            <input name="description" />
          </FieldShell>
          {!custom && !trust && (
            <FieldShell label="Or a trust policy" rule={RULES.trust}>
              <textarea name="trust" placeholder='{"Version": "2012-10-17", "Statement": [...]}' />
            </FieldShell>
          )}
        </MoreFields>
      </div>
    </>
  );
}

/** A new policy from a template. `inline` is the inline policy form: its name
 * field is `policyName` and there is no description. */
export function PolicyFields({ taken, inline }: { taken: string[]; inline?: boolean }) {
  const [preset, setPreset] = useState<PolicyPreset>(POLICY_PRESETS[0]);
  return (
    <>
      <PresetGallery presets={POLICY_PRESETS.map((p) => ({ ...p, title: p.description ?? p.label, added: taken.includes(p.name) }))} chosen={preset.id} choose={setPreset} label="Allows" size={26} />
      <div key={preset.id} className="preset-fields">
        <FieldShell label="Name" rule={inline ? RULES.inlinePolicyName : RULES.policyName} taken={taken} unique>
          <input name={inline ? "policyName" : "name"} required defaultValue={preset.name ? freeName(preset.name, taken) : undefined} />
        </FieldShell>
        <FieldShell label="Document" rule={RULES.document}>
          <textarea name="document" rows={12} required aria-label="Policy document" className="code-editor" spellCheck={false} defaultValue={policyJson(preset)} />
        </FieldShell>
        {!inline && (
          <MoreFields>
            <FieldShell label="Description" rule={RULES.policyDescription}>
              <input name="description" defaultValue={preset.description} />
            </FieldShell>
          </MoreFields>
        )}
      </div>
    </>
  );
}

/** The attach form: the common AWS managed policies as tiles, or any ARN. */
export function AttachFields({ known, attached }: { known: { arn: string; name: string }[]; attached: string[] }) {
  const [arn, setArn] = useState("");
  const tiles = COMMON_POLICIES.map((p) => ({ ...p, added: attached.includes(managedArn(p.id)) }));
  const chosen = COMMON_POLICIES.find((p) => managedArn(p.id) === arn)?.id;
  return (
    <>
      <PresetGallery presets={tiles} chosen={chosen} choose={(p) => setArn(managedArn(p.id))} label="AWS managed" size={24} testId="policy" />
      <FieldShell label="Policy" rule={RULES.policyArn} known={known.map((p) => p.arn)}>
        <input name="policyArn" list="policies" required value={arn} onChange={(e) => setArn(e.target.value)} placeholder="arn:aws:iam::aws:policy/ReadOnlyAccess" />
      </FieldShell>
      <datalist id="policies">
        {known.map((p) => (
          <option key={p.arn} value={p.arn}>
            {p.name}
          </option>
        ))}
      </datalist>
    </>
  );
}

/** A new OIDC provider from a logo: the issuer URL and audience filled in. */
export function OidcFields({ urls }: { urls: string[] }) {
  const [preset, setPreset] = useState<OidcPreset>(OIDC_PRESETS[0]);
  const items = OIDC_PRESETS.map((p) => ({ ...p, title: p.url || p.label, added: !!p.url && !p.tenant && urls.includes(p.url.replace(/^https:\/\//, "")) }));
  return (
    <>
      <PresetGallery presets={items} chosen={preset.id} choose={setPreset} label="Provider" size={24} />
      <div key={preset.id} className="preset-fields">
        <FieldShell label="Provider URL" rule={CreateOpenIDConnectProvider.Url} format="url">
          <input name="url" required defaultValue={preset.url} autoFocus={preset.tenant} placeholder="https://token.actions.githubusercontent.com" />
        </FieldShell>
        <FieldShell label="Audiences" rule={CreateOpenIDConnectProvider.ClientIDList}>
          <input name="clients" defaultValue={preset.audience} placeholder="sts.amazonaws.com" />
        </FieldShell>
        <MoreFields>
          <FieldShell label="Thumbprints" rule={CreateOpenIDConnectProvider.ThumbprintList} hint="Optional: 40 hex characters each">
            <input name="thumbprints" />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}
