"use client";

// The create-stack sheet opens on starter templates: picking one fills the
// template, a free stack name and the capabilities it needs, in three
// steps: template, details, options.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateStack as CreateStackRules } from "@mws-dashboard/ui/model/cloudformation";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { Section, Sections } from "@mws-dashboard/ui/sections";
import { useState } from "react";

import { PARAMETERS, STACK_NAME, TEMPLATE } from "../../lib/cloudformation";
import { STARTERS, type StarterTemplate } from "../../lib/templates";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

const CAPABILITIES = [
  ["CAPABILITY_IAM", "IAM resources"],
  ["CAPABILITY_NAMED_IAM", "Named IAM resources"],
  ["CAPABILITY_AUTO_EXPAND", "Macros (auto-expand)"],
] as const;

function Capabilities({ checked = [] }: { checked?: string[] }) {
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

export function StackFields({ names }: { names: string[] }) {
  const [starter, setStarter] = useState<StarterTemplate>(STARTERS[0]);
  const needs = starter.capabilities ?? [];
  return (
    <Sections testId="stack">
      <Section id="template" label="Template" summary={starter.label}>
        <PresetGallery presets={STARTERS} chosen={starter.id} choose={setStarter} label="Template" size={26} />
        <div key={starter.id} className="preset-fields">
          <FieldShell label="Template" rule={{ ...CreateStackRules.TemplateBody, ...TEMPLATE }}>
            <textarea name="template" rows={12} required className="code-editor" spellCheck={false} defaultValue={starter.body} />
          </FieldShell>
        </div>
      </Section>
      <Section id="details" label="Details">
        <div key={starter.id} className="preset-fields">
          <FieldShell label="Stack name" rule={{ ...CreateStackRules.StackName, ...STACK_NAME }} taken={names} unique>
            <input name="name" required maxLength={128} defaultValue={freeName(starter.base, names)} />
          </FieldShell>
          <FieldShell label="Parameters" rule={PARAMETERS} hint="Empty uses the template's defaults">
            <textarea name="parameters" rows={2} placeholder="Env=prod" spellCheck={false} />
          </FieldShell>
          <Capabilities checked={needs} />
        </div>
      </Section>
      <Section id="options" label="Options">
        <div className="form-row">
          <FieldShell label="On failure">
            <select name="onFailure" defaultValue="ROLLBACK">
              <option value="ROLLBACK">Roll back</option>
              <option value="DO_NOTHING">Preserve resources</option>
              <option value="DELETE">Delete</option>
            </select>
          </FieldShell>
          <FieldShell label="Timeout (minutes)" rule={CreateStackRules.TimeoutInMinutes}>
            <input name="timeout" type="number" min={1} />
          </FieldShell>
        </div>
        <FieldShell label="Service role" rule={CreateStackRules.RoleARN} format="arn">
          <ResourcePicker kind="iam-role" name="role" service="cloudformation.amazonaws.com" />
        </FieldShell>
        <label className="check">
          <input type="checkbox" name="protect" /> Termination protection
        </label>
        <MoreFields>
          <FieldShell label="Notification topics" rule={CreateStackRules.NotificationARNs} hint="SNS topic ARNs">
            <ResourcePicker kind="sns-topic" name="notifications" multiple />
          </FieldShell>
          <FieldShell label="Tags" format="tags">
            <textarea name="tags" rows={2} placeholder="team=platform" spellCheck={false} />
          </FieldShell>
        </MoreFields>
      </Section>
    </Sections>
  );
}
