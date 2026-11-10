"use client";

// EKS create forms that open on tiles: a node group starts from a kind of
// node (general, Spot, Graviton, GPU), an add-on from its logo.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateNodegroup } from "@mws-dashboard/ui/model/eks";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { Puzzle } from "lucide-react";
import { useState, type ReactNode } from "react";

import { NODE_PRESETS, addonIcon, type NodePreset } from "./presets";
import { Scaling } from "./scaling.tsx";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

export function NodegroupFields({ rule, taken, types, children }: { rule: Rule; taken: string[]; types: string[]; children?: ReactNode }) {
  const [preset, setPreset] = useState<NodePreset>(NODE_PRESETS[0]);
  return (
    <>
      <PresetGallery presets={NODE_PRESETS} chosen={preset.id} choose={setPreset} label="Nodes" size={26} />
      <div key={preset.id} className="preset-fields">
        <FieldShell label="Name" rule={rule} taken={taken} unique>
          <input name="name" defaultValue={freeName(preset.id === "general" ? "nodes" : preset.id, taken)} />
        </FieldShell>
        {children}
        <FieldShell label="Instance type" member="instanceTypes" rule={types.length ? { required: true, enum: types } : { required: true }}>
          <input name="type" defaultValue={preset.type} list="eks-instance-types" autoComplete="off" />
        </FieldShell>
        <datalist id="eks-instance-types">
          {types.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
        <Scaling rules={CreateNodegroup.scalingConfig.fields!} names={{ desired: "size", max: "max" }} defaults={{ desired: preset.desired, max: preset.max }} />
        <MoreFields>
          <FieldShell label="AMI type" rule={CreateNodegroup.amiType}>
            <select name="amiType" defaultValue={preset.amiType}>
              {(CreateNodegroup.amiType.enum ?? []).map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </FieldShell>
          <label className="check">
            <input type="checkbox" name="spot" defaultChecked={preset.spot} /> Spot capacity
          </label>
        </MoreFields>
      </div>
    </>
  );
}

export interface OfferedAddon {
  name: string;
  publisher?: string;
  versions: string[];
  /** The version EKS marks as default for this cluster. */
  default?: string;
}

export function AddonFields({ offered }: { offered: OfferedAddon[] }) {
  const [chosen, setChosen] = useState(offered[0]?.name);
  const addon = offered.find((a) => a.name === chosen);
  const items = offered.map((a) => {
    const icon = addonIcon(a.name);
    return { id: a.name, label: a.name, icon: icon ?? <Puzzle size={24} aria-hidden />, title: a.publisher ? `${a.name} · ${a.publisher}` : a.name, group: a.publisher === "eks" || !a.publisher ? "Amazon EKS" : "Partners" };
  });
  return (
    <>
      <PresetGallery presets={items} chosen={chosen} choose={(p) => setChosen(p.id)} label="Add-on" size={26} testId="addon" />
      <input type="hidden" name="addon" value={chosen ?? ""} />
      <MoreFields key={chosen}>
        <FieldShell label="Version">
          <select name="version" defaultValue="">
            <option value="">{addon?.default ? `Default (${addon.default})` : "Default"}</option>
            {(addon?.versions ?? []).map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </FieldShell>
        <FieldShell label="Service account role ARN" format="arn">
          <ResourcePicker kind="iam-role" name="role" placeholder="optional" />
        </FieldShell>
        <FieldShell label="Configuration values" format="jsonish">
          <textarea name="config" rows={3} spellCheck={false} placeholder="optional JSON or YAML" />
        </FieldShell>
      </MoreFields>
    </>
  );
}
