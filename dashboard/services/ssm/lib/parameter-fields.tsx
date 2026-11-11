"use client";

// The parameter sheet's fields. A new parameter starts from what it holds
// (text, a secret, a list, an AMI ID): the choice sets Type and Data type,
// and only Name and Value stay in view. Tier, KMS key, policies and the
// rest wait under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import { PutParameter } from "@mws-dashboard/ui/model/ssm";
import type { Rule } from "@mws-dashboard/ui/validation";
import { Braces, List } from "lucide-react";
import { useState } from "react";

import type { ParameterDefaults } from "./parameter-form";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

// The model only bounds the name's length; the rest is Parameter Store's
// documented naming rules (MWS enforces the same): a name or a /path of up
// to 15 levels, and nothing under aws or ssm.
export const NAME: Rule = {
  ...PutParameter.Name,
  pattern: "^(?:[A-Za-z0-9_.-]+|(?:[/][A-Za-z0-9_.-]+){1,15})$",
  reserved: ["/aws", "/ssm", "aws", "ssm", "/AWS", "/SSM", "AWS", "SSM"],
  hint: "Like /app/prod/db-host",
};
// Standard holds up to 4 KB, Advanced (and Intelligent-Tiering past 4 KB) 8 KB.
const VALUE = (tier: string | undefined): Rule => ({ ...PutParameter.Value, maxLength: tier === "Standard" ? 4096 : 8192 });
const POLICIES: Rule = { ...PutParameter.Policies, format: "json" };

interface Kind extends PresetItem {
  type: "String" | "StringList" | "SecureString";
  dataType: string;
  placeholder: string;
  hint?: string;
}

const KINDS: Kind[] = [
  { id: "text", label: "Text", icon: "resource/AWSSystemsManagerParameterStore", type: "String", dataType: "text", placeholder: "db.internal:5432" },
  { id: "secure", label: "Secret", icon: "service/AWSKeyManagementService", type: "SecureString", dataType: "text", placeholder: "s3cret", title: "SecureString, encrypted with KMS" },
  { id: "list", label: "List", icon: <List size={26} aria-hidden />, type: "StringList", dataType: "text", placeholder: "a,b,c", hint: "Comma-separated" },
  { id: "json", label: "JSON", icon: <Braces size={26} aria-hidden />, type: "String", dataType: "text", placeholder: '{"retries": 3}' },
  { id: "ami", label: "AMI ID", icon: "resource/AmazonEC2AMI", type: "String", dataType: "aws:ec2:image", placeholder: "ami-0123456789abcdef0", title: "Validated as an EC2 image ID" },
];

export function ParameterFields({ defaults, keys }: { defaults: ParameterDefaults; keys: string[] }) {
  const [kind, setKind] = useState<Kind>(KINDS[0]);
  const edit = !!defaults.overwrite;
  const tier = defaults.tier ?? "Standard";
  const type = edit ? (defaults.type ?? "String") : kind.type;
  const secure = type === "SecureString";
  return (
    <>
      {!edit && <PresetGallery presets={KINDS} chosen={kind.id} choose={setKind} label="Holds" size={26} />}
      <div key={edit ? defaults.name : kind.id} className="preset-fields">
        {edit ? (
          <input type="hidden" name="name" value={defaults.name} />
        ) : (
          <FieldShell label="Name" rule={{ ...NAME, generate: { prefix: defaults.path || "/" } }} taken={defaults.taken} unique>
            <input name="name" required defaultValue={defaults.name} placeholder="/app/prod/db-host" />
          </FieldShell>
        )}
        <FieldShell
          label="Value"
          rule={{ ...VALUE(tier), required: !defaults.keepValue }}
          format={!edit && kind.id === "json" ? "json" : undefined}
          hint={defaults.keepValue ? "Empty keeps the current value" : kind.hint}
        >
          <textarea
            name="value"
            rows={kind.id === "json" ? 5 : 3}
            className={kind.id === "json" ? "code-editor" : undefined}
            spellCheck={false}
            required={!defaults.keepValue}
            defaultValue={defaults.value}
            placeholder={edit ? undefined : kind.placeholder}
          />
        </FieldShell>
        {defaults.keepValue && <input type="hidden" name="keep" value="on" />}
        {!edit && (
          <>
            <input type="hidden" name="type" value={kind.type} />
            <input type="hidden" name="dataType" value={kind.dataType} />
          </>
        )}
        <MoreFields>
          <FieldShell label="Description" rule={PutParameter.Description}>
            <input name="description" defaultValue={defaults.description} />
          </FieldShell>
          <div className="form-row">
            <FieldShell label="Tier" rule={PutParameter.Tier}>
              {/* A parameter can move up to Advanced, never back down. */}
              <select name="tier" defaultValue={tier}>
                {(tier === "Advanced" ? ["Advanced"] : ["Standard", "Advanced", "Intelligent-Tiering"]).map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </FieldShell>
            {edit && (
              <>
                <FieldShell label="Type" rule={PutParameter.Type}>
                  <select name="type" defaultValue={type}>
                    <option>String</option>
                    <option>StringList</option>
                    <option>SecureString</option>
                  </select>
                </FieldShell>
                <FieldShell label="Data type" rule={PutParameter.DataType}>
                  <select name="dataType" defaultValue={defaults.dataType ?? "text"}>
                    <option value="text">text</option>
                    <option value="aws:ec2:image">aws:ec2:image</option>
                    <option value="aws:ssm:integration">aws:ssm:integration</option>
                  </select>
                </FieldShell>
              </>
            )}
          </div>
          {(secure || edit) && (
            <FieldShell label="KMS key (SecureString)" rule={PutParameter.KeyId} known={keys} hint="Empty: alias/aws/ssm">
              <ResourcePicker kind="kms-key" name="keyId" defaultValue={defaults.keyId} placeholder="alias/aws/ssm" />
            </FieldShell>
          )}
          <FieldShell label="Allowed pattern" rule={PutParameter.AllowedPattern}>
            <input name="allowedPattern" defaultValue={defaults.allowedPattern} placeholder="^\d+$" />
          </FieldShell>
          <FieldShell label="Policies (Advanced tier)" rule={POLICIES}>
            <textarea name="policies" rows={4} className="code-editor" spellCheck={false} defaultValue={defaults.policies} placeholder='[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2027-01-01T00:00:00.000Z"}}]' />
          </FieldShell>
          {!edit && (
            <FieldShell label="Tags" format="tags">
              <textarea name="tags" rows={2} placeholder="team=payments" />
            </FieldShell>
          )}
        </MoreFields>
      </div>
    </>
  );
}
