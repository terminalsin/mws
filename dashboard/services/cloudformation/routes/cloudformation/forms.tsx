import { ActionForm, Field, Sheet } from "@mws-dashboard/ui";
import { CreateChangeSet as ChangeSetRules, CreateStack as CreateStackRules } from "@mws-dashboard/ui/model/cloudformation";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { GitCompare } from "lucide-react";

import { PARAMETERS, SAMPLE_TEMPLATE, STACK_NAME, TEMPLATE } from "../../lib/cloudformation";
import { createChangeSet, createStack } from "./actions";
import { StackFields } from "./stack-fields";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

const CAPABILITIES = [
  ["CAPABILITY_IAM", "IAM resources"],
  ["CAPABILITY_NAMED_IAM", "Named IAM resources"],
  ["CAPABILITY_AUTO_EXPAND", "Macros (auto-expand)"],
] as const;

/** The acknowledgments AWS asks for before it creates IAM resources or runs macros. */
export function Capabilities({ checked = [] }: { checked?: string[] }) {
  return (
    <fieldset className="checks">
      <legend>Capabilities</legend>
      {CAPABILITIES.map(([value, label]) => (
        <label key={value} className="check">
          <input type="checkbox" name="capabilities" value={value} defaultChecked={checked.includes(value)} /> {label}
        </label>
      ))}
    </fieldset>
  );
}

function Role() {
  return (
    <Field label="Service role" rule={CreateStackRules.RoleARN} format="arn">
      <ResourcePicker kind="iam-role" name="role" service="cloudformation.amazonaws.com" />
    </Field>
  );
}

function TagsField() {
  return (
    <Field label="Tags" format="tags">
      <textarea name="tags" rows={2} placeholder="team=platform" spellCheck={false} />
    </Field>
  );
}

export function CreateStack({ names }: { names: string[] }) {
  return (
    <Sheet title="Create stack" label="Create stack" testId="create-stack">
      <ActionForm action={createStack} submit="Create stack" testId="create-stack">
        <StackFields names={names} />
      </ActionForm>
    </Sheet>
  );
}

/** A change set: for an existing stack (an update or an import), or a new
 * stack created or imported through one, which then waits in
 * REVIEW_IN_PROGRESS until it is executed. */
export function CreateChangeSet({
  stack,
  template,
  parameters = "",
  previous = {},
  names = [],
  taken = [],
}: {
  stack?: string;
  template?: string;
  parameters?: string;
  previous?: Record<string, string>;
  names?: string[];
  taken?: string[];
}) {
  return (
    <Sheet title="Create change set" label="Create change set" icon={<GitCompare size={16} />} testId="create-change-set">
      <ActionForm action={createChangeSet.bind(null, stack ?? null, previous)} submit="Create change set" testId="create-change-set">
        {!stack && (
          <Field label="Stack name" rule={{ ...ChangeSetRules.StackName, ...STACK_NAME }} taken={names}>
            <input name="name" required maxLength={128} />
          </Field>
        )}
        <div className="form-row">
          <Field label="Change set name" rule={{ ...ChangeSetRules.ChangeSetName, generate: "name" }} taken={taken} unique>
            <input name="changeSet" required maxLength={128} />
          </Field>
          <Field label="Type">
            <select name="type" defaultValue={stack ? "UPDATE" : "CREATE"}>
              {stack ? <option value="UPDATE">Update</option> : <option value="CREATE">Create</option>}
              <option value="IMPORT">Import resources</option>
            </select>
          </Field>
        </div>
        <Field label="Template" rule={{ ...ChangeSetRules.TemplateBody, ...TEMPLATE }}>
          <textarea name="template" rows={14} required className="code-editor" spellCheck={false} defaultValue={template ?? SAMPLE_TEMPLATE} />
        </Field>
        <Field label="Parameters" rule={PARAMETERS} hint={Object.values(previous).includes("****") ? "Leave **** to keep a hidden value" : undefined}>
          <textarea name="parameters" rows={2} spellCheck={false} defaultValue={parameters} />
        </Field>
        <Field label="Resources to import" format="pairs" hint="For an import: LogicalId=identifier, e.g. Bucket=my-bucket">
          <textarea name="imports" rows={2} spellCheck={false} placeholder="Bucket=my-existing-bucket" />
        </Field>
        <MoreFields>
          <Field label="Description" rule={ChangeSetRules.Description}>
            <input name="description" />
          </Field>
          <Capabilities />
          <Role />
          {!stack && <TagsField />}
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
}
