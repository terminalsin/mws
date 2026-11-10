"use client";

// A new association starts from what it keeps in place: a shell command,
// patching, inventory or the SSM Agent's version. The choice picks the
// document, a schedule and its parameters; tuning waits under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateAssociation } from "@mws-dashboard/ui/model/ssm";
import { MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import { Wrench } from "lucide-react";
import { useState } from "react";

export interface AssociationDefaults {
  document?: string;
  name?: string;
  targets?: string;
  schedule?: string;
  parameters?: string;
  maxConcurrency?: string;
  maxErrors?: string;
  severity?: string;
}

interface Kind extends PresetItem {
  document: string;
  schedule: string;
  parameters?: string;
}

const KINDS: Kind[] = [
  { id: "shell", label: "Shell command", icon: "brand/gnubash", document: "AWS-RunShellScript", schedule: "rate(30 minutes)", parameters: "commands=uptime" },
  { id: "patch", label: "Patch scan", icon: "resource/AWSSystemsManagerPatchManager", document: "AWS-RunPatchBaseline", schedule: "cron(0 2 ? * SUN *)", parameters: "Operation=Scan", title: "AWS-RunPatchBaseline, Sundays 02:00" },
  { id: "inventory", label: "Inventory", icon: "resource/AWSSystemsManagerInventory", document: "AWS-GatherSoftwareInventory", schedule: "rate(1 day)", title: "AWS-GatherSoftwareInventory, daily" },
  { id: "agent", label: "Update agent", icon: "service/AWSSystemsManager", document: "AWS-UpdateSSMAgent", schedule: "rate(14 days)", title: "AWS-UpdateSSMAgent, every two weeks" },
  { id: "custom", label: "Other document", icon: <Wrench size={22} aria-hidden />, document: "", schedule: "" },
];

/** The fields CreateAssociation and UpdateAssociation share. */
export function AssociationFields({ documents, defaults = {}, fixedDocument }: { documents: string[]; defaults?: AssociationDefaults; fixedDocument?: boolean }) {
  const [kind, setKind] = useState<Kind>(KINDS[0]);
  const custom = !fixedDocument && kind.id === "custom";
  const d = (own: string | undefined, preset: string | undefined) => (fixedDocument ? own : preset);
  return (
    <>
      {!fixedDocument && <PresetGallery presets={KINDS} chosen={kind.id} choose={setKind} label="Keeps in place" size={26} />}
      <div key={fixedDocument ? "edit" : kind.id} className="preset-fields">
        {custom && (
          <FieldShell label="Document" rule={CreateAssociation.Name} known={documents}>
            <input name="document" required defaultValue={defaults.document} list="ssm-documents" placeholder="AWS-RunShellScript" />
          </FieldShell>
        )}
        {!fixedDocument && !custom && <input type="hidden" name="document" value={kind.document} />}
        <FieldShell label="Association name" rule={CreateAssociation.AssociationName} unique>
          <input name="name" defaultValue={defaults.name} />
        </FieldShell>
        <FieldShell label="Targets" hint="InstanceIds=i-1,i-2 · tag:env=prod · InstanceIds=* (one a line)" member="Targets">
          <textarea name="targets" rows={2} required defaultValue={defaults.targets ?? "InstanceIds=*"} />
        </FieldShell>
        <FieldShell label="Schedule" rule={{ ...CreateAssociation.ScheduleExpression, hint: "rate(30 minutes) or cron(0 2 ? * SUN *)" }}>
          <input name="schedule" defaultValue={d(defaults.schedule, kind.schedule)} placeholder="rate(30 minutes)" />
        </FieldShell>
        <FieldShell label="Parameters" hint="name=value, one a line; indented lines continue a list (commands)" member="Parameters">
          <textarea name="parameters" rows={3} className="code-editor" spellCheck={false} defaultValue={d(defaults.parameters, kind.parameters)} placeholder={"commands=echo hello\n  uptime"} />
        </FieldShell>
        <MoreFields expanded={!!(defaults.maxConcurrency || defaults.maxErrors || defaults.severity)}>
          <div className="form-row">
            <FieldShell label="Concurrency" rule={CreateAssociation.MaxConcurrency}>
              <input name="maxConcurrency" defaultValue={defaults.maxConcurrency} placeholder="50" />
            </FieldShell>
            <FieldShell label="Error threshold" rule={CreateAssociation.MaxErrors}>
              <input name="maxErrors" defaultValue={defaults.maxErrors} placeholder="0" />
            </FieldShell>
            <FieldShell label="Compliance severity" rule={CreateAssociation.ComplianceSeverity}>
              <select name="severity" defaultValue={defaults.severity ?? ""}>
                <option value="">Unspecified</option>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
            </FieldShell>
          </div>
          {!fixedDocument && (
            <label className="check">
              <input type="checkbox" name="cronOnly" /> Apply only at the next scheduled time
            </label>
          )}
        </MoreFields>
      </div>
      <datalist id="ssm-documents">
        {documents.map((doc) => (
          <option key={doc} value={doc} />
        ))}
      </datalist>
    </>
  );
}
