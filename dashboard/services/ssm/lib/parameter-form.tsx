import { ActionForm, Field, type Rule } from "@mws-dashboard/ui";
import { PutParameter } from "@mws-dashboard/ui/model/ssm";

import { putParameter } from "../routes/ssm/actions";

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

export interface ParameterDefaults {
  name?: string;
  value?: string;
  type?: string;
  tier?: string;
  keyId?: string;
  description?: string;
  allowedPattern?: string;
  dataType?: string;
  policies?: string;
  /** Saving over an existing parameter (its name is fixed). */
  overwrite?: boolean;
  /** A SecureString whose value is hidden: an empty value keeps it. */
  keepValue?: boolean;
  path?: string;
  taken?: string[];
}

/** Every PutParameter input: what AWS's create and edit forms ask. */
export function ParameterForm({ defaults, keys, testId }: { defaults: ParameterDefaults; keys: string[]; testId?: string }) {
  const tier = defaults.tier ?? "Standard";
  return (
    <ActionForm action={putParameter} submit="Save" testId={testId}>
      {defaults.overwrite ? (
        <input type="hidden" name="name" value={defaults.name} />
      ) : (
        <Field label="Name" rule={{ ...NAME, generate: { prefix: defaults.path || "/" } }} taken={defaults.taken} unique>
          <input name="name" required defaultValue={defaults.name} placeholder="/app/prod/db-host" />
        </Field>
      )}
      <Field label="Description" rule={PutParameter.Description}>
        <input name="description" defaultValue={defaults.description} />
      </Field>
      <div className="form-row">
        <Field label="Tier" rule={PutParameter.Tier}>
          {/* A parameter can move up to Advanced, never back down. */}
          <select name="tier" defaultValue={tier}>
            {(tier === "Advanced" ? ["Advanced"] : ["Standard", "Advanced", "Intelligent-Tiering"]).map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </Field>
        <Field label="Type" rule={PutParameter.Type}>
          <select name="type" defaultValue={defaults.type ?? "String"}>
            <option>String</option>
            <option>StringList</option>
            <option>SecureString</option>
          </select>
        </Field>
        <Field label="Data type" rule={PutParameter.DataType}>
          <select name="dataType" defaultValue={defaults.dataType ?? "text"}>
            <option value="text">text</option>
            <option value="aws:ec2:image">aws:ec2:image</option>
            <option value="aws:ssm:integration">aws:ssm:integration</option>
          </select>
        </Field>
      </div>
      <Field label="KMS key (SecureString)" rule={PutParameter.KeyId} known={keys} hint="Empty: alias/aws/ssm">
        <input name="keyId" defaultValue={defaults.keyId} placeholder="alias/aws/ssm" />
      </Field>
      <Field label="Value" rule={{ ...VALUE(tier), required: !defaults.keepValue }} hint={defaults.keepValue ? "Empty keeps the current value" : undefined}>
        <textarea name="value" rows={4} required={!defaults.keepValue} defaultValue={defaults.value} />
      </Field>
      {defaults.keepValue && <input type="hidden" name="keep" value="on" />}
      <details>
        <summary>Advanced</summary>
        <Field label="Allowed pattern" rule={PutParameter.AllowedPattern}>
          <input name="allowedPattern" defaultValue={defaults.allowedPattern} placeholder="^\d+$" />
        </Field>
        <Field label="Policies (Advanced tier)" rule={POLICIES}>
          <textarea name="policies" rows={4} className="code-editor" spellCheck={false} defaultValue={defaults.policies} placeholder='[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2027-01-01T00:00:00.000Z"}}]' />
        </Field>
        {!defaults.overwrite && (
          <Field label="Tags" format="tags">
            <textarea name="tags" rows={2} placeholder="team=payments" />
          </Field>
        )}
      </details>
      {defaults.overwrite && <input type="hidden" name="overwrite" value="on" />}
    </ActionForm>
  );
}
