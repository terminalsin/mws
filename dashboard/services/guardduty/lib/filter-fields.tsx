"use client";

// A suppression rule's fields. A new rule starts from the finding it
// silences: picking a tile fills the finding type, resource and a name, so
// the common case is one click and Create. Severity, action, rank and the
// description wait under More.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateFilter } from "@mws-dashboard/ui/model/guardduty";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import { Wrench } from "lucide-react";
import { useState } from "react";

import { SUPPRESSION_PRESETS, nameFromType, type SuppressionPreset } from "./presets";

// The model only bounds the length; GuardDuty's own check allows these.
const NAME: Rule = { ...CreateFilter.Name, pattern: "^[A-Za-z0-9._-]+$", hint: "Letters, digits, ., - and _", generate: "name" };
// ThreatPurpose:ResourceType/ThreatFamily.Mechanism!Artifact
const ONE = "[A-Za-z]+:[A-Za-z0-9]+/[A-Za-z0-9.!&_-]+";
const TYPE: Rule = { required: true, pattern: `^${ONE}(\\s*,\\s*${ONE})*$`, hint: "Like Recon:EC2/PortProbeUnprotectedPort (comma-separate several)" };
export const RESOURCES = ["Instance", "AccessKey", "S3Bucket", "S3Object", "EKSCluster", "ECSCluster", "Container", "Lambda", "RDSDBInstance", "EBSVolume"];

export interface SavedFilter {
  name: string;
  description?: string;
  action: string;
  rank?: number;
  criteria: string[];
  types: string[];
  severity?: number;
  resource?: string;
}

const CUSTOM: SuppressionPreset = { id: "custom", label: "Custom", icon: "", type: "" };

export function FilterFields({
  types,
  f,
  names = [],
  ruled = [],
  like,
}: {
  /** Finding types seen in this Region, for suggestions. */
  types: string[];
  /** The rule being edited. */
  f?: SavedFilter;
  names?: string[];
  /** Finding types existing rules already cover: a check on their tile. */
  ruled?: string[];
  /** Start from this finding's type and resource ("suppress findings like this"). */
  like?: { type: string; resource?: string; icon: string };
}) {
  const own: SuppressionPreset | undefined = like && { id: "this-finding", label: "This finding", icon: like.icon, type: like.type, resource: like.resource };
  const presets = [...(own ? [own] : []), ...SUPPRESSION_PRESETS.filter((p) => p.type !== like?.type)];
  const [preset, setPreset] = useState<SuppressionPreset>(presets[0]);
  // Seen in this Region's findings: a green dot.
  const seen = (p: SuppressionPreset) => p.type.split(",").some((t) => types.includes(t.trim()));
  const v = f
    ? { type: f.types.join(", "), resource: f.resource ?? "", severity: f.severity === undefined ? "" : String(f.severity) }
    : { type: preset.type, resource: preset.resource ?? "", severity: preset.severity ?? "" };
  const base = preset.id === "custom" ? undefined : preset.id === "this-finding" ? nameFromType(preset.type) : preset.id;
  return (
    <>
      {!f && (
        <PresetGallery
          label="Findings to suppress"
          presets={[
            ...presets.map((p) => ({ ...p, found: p.id !== "this-finding" && seen(p), added: p.type.split(",").every((t) => ruled.includes(t.trim())), title: p.type })),
            { ...CUSTOM, icon: <Wrench size={22} aria-hidden /> },
          ]}
          chosen={preset.id}
          choose={(p) => setPreset(p.id === "custom" ? CUSTOM : (presets.find((x) => x.id === p.id) ?? CUSTOM))}
          testId="suppression-preset"
        />
      )}
      <div key={f?.name ?? preset.id} className="preset-fields">
        {!f && (
          <FieldShell label="Name" rule={NAME} taken={names} unique>
            <input name="name" required defaultValue={base ? freeName(base, names) : undefined} />
          </FieldShell>
        )}
        <FieldShell label="Finding type" rule={TYPE} known={types}>
          <input name="type" list="guardduty-finding-types" required autoComplete="off" defaultValue={v.type} />
        </FieldShell>
        <datalist id="guardduty-finding-types">
          {types.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
        <MoreFields open={!!f || preset.id === "custom"}>
          <div className="form-row">
            <FieldShell label="Minimum severity">
              <select name="severity" defaultValue={v.severity}>
                <option value="">Any</option>
                <option value="9">Critical</option>
                <option value="7">High</option>
                <option value="4">Medium</option>
                <option value="1">Low</option>
              </select>
            </FieldShell>
            <FieldShell label="Resource type">
              <select name="resource" defaultValue={v.resource}>
                <option value="">Any</option>
                {RESOURCES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </FieldShell>
          </div>
          <div className="form-row">
            <FieldShell label="Action">
              <select name="action" defaultValue={f?.action ?? "ARCHIVE"}>
                <option value="ARCHIVE">Suppress (archive)</option>
                <option value="NOOP">Saved filter only</option>
              </select>
            </FieldShell>
            <FieldShell label="Rank" rule={CreateFilter.Rank}>
              <input name="rank" type="number" min={1} max={100} defaultValue={f?.rank} />
            </FieldShell>
          </div>
          <FieldShell label="Description" rule={CreateFilter.Description}>
            <input name="description" defaultValue={f?.description} />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}
