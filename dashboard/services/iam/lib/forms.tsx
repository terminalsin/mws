"use client";

// IAM's create forms open on tiles: a role starts from who trusts it (and
// attaches the managed policy that kind of role usually needs), a policy
// from what it allows.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateOpenIDConnectProvider } from "@mws-dashboard/ui/model/iam";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";
import { PolicyEditor } from "@mws-dashboard/ui/policy";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { COMMON_POLICIES, OIDC_PRESETS, POLICY_PRESETS, ROLE_PRESETS, managedArn, policyJson, presetTrust, type OidcPreset, type PolicyPreset, type RolePreset } from "./presets";
import { RULES } from "./rules";

export function RoleFields({ taken, account }: { taken: string[]; account: string | null }) {
  const [preset, setPreset] = useState<RolePreset>(ROLE_PRESETS[0]);
  const custom = preset.trust === "custom";
  const trust = presetTrust(preset, account);
  const policy = preset.attach?.split("/").pop();
  return (
    <>
      <PresetGallery presets={ROLE_PRESETS.map((p) => ({ ...p, title: p.service ?? p.label }))} chosen={preset.id} choose={setPreset} label="Trusted entity" size={26} />
      <div key={preset.id} className="preset-fields">
        <FieldShell label="Name" rule={RULES.roleName} taken={taken} unique>
          <input name="name" required defaultValue={preset.name ? freeName(preset.name, taken) : undefined} autoFocus={custom} />
        </FieldShell>
        {preset.service && <input type="hidden" name="service" value={preset.service} />}
        <PolicyEditor
          label="Trust policy"
          name="trust"
          kind="trust"
          rows={10}
          required={custom}
          rule={{ ...RULES.trust, required: custom }}
          defaultValue={trust}
          startIn={custom ? "json" : "visual"}
          hint={preset.trust === "github" ? "Replace OWNER/REPO with the repository that deploys" : undefined}
          testId="trust-editor"
        />
        <FieldShell label="Permissions" hint="AWS and customer managed policies to attach">
          <ResourcePicker kind="iam-policy" name="policies" multiple defaultValue={preset.attach ? `${preset.attach}, ` : undefined} placeholder="Search managed policies" testId="role-policies" />
        </FieldShell>
        {policy && <input type="hidden" name="suggested" value={preset.attach} />}
        <MoreFields>
          <FieldShell label="Description" rule={RULES.roleDescription}>
            <input name="description" />
          </FieldShell>
          <FieldShell label="Permissions boundary" rule={{ ...RULES.policyArn, required: false }}>
            <ResourcePicker kind="iam-policy" name="boundary" placeholder="Optional: the most this role may ever do" />
          </FieldShell>
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
        <PolicyEditor label="Document" name="document" rule={RULES.document} required defaultValue={policyJson(preset)} testId="policy-editor" />
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

/** The attach form: the common AWS managed policies as tiles, or any policy, searched. */
export function AttachFields({ attached }: { known?: { arn: string; name: string }[]; attached: string[] }) {
  const [arn, setArn] = useState("");
  const tiles = COMMON_POLICIES.map((p) => ({ ...p, added: attached.includes(managedArn(p.id)) }));
  const chosen = COMMON_POLICIES.find((p) => managedArn(p.id) === arn)?.id;
  return (
    <>
      <PresetGallery presets={tiles} chosen={chosen} choose={(p) => setArn(managedArn(p.id))} label="AWS managed" size={24} testId="policy" />
      <FieldShell label="Policy" rule={RULES.policyArn}>
        <ResourcePicker kind="iam-policy" name="policyArn" required value={arn} onValueChange={setArn} placeholder="Search AWS and customer managed policies" testId="attach-policy" />
      </FieldShell>
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
