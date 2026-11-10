"use client";

// Fields that follow other choices: the subnets and target groups offered
// are the chosen VPC's; a scheduled action is one-time or recurring; a
// scaling policy's fields follow its type.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import type { Rule } from "@mws-dashboard/ui";
import { PutScalingPolicy, PutScheduledUpdateGroupAction } from "@mws-dashboard/ui/model/autoscaling";
import { MoreFields, PresetGallery, freeName, type PresetItem } from "@mws-dashboard/ui/presets";
import { ArrowDownToLine, ArrowUpFromLine, ChartNoAxesColumnIncreasing, Cpu, Crosshair, Plus } from "lucide-react";
import { useState } from "react";

import { PolicyTarget } from "./sizes";

export interface VpcOption {
  id: string;
  label: string;
  default: boolean;
}
export interface SubnetOption {
  id: string;
  vpc: string;
  label: string;
  az: string;
}
export interface TargetGroupOption {
  arn: string;
  name: string;
  vpc?: string;
}

export function NetworkFields({
  vpcs,
  subnets,
  targetGroups,
  vpc: initial,
  checked,
}: {
  vpcs: VpcOption[];
  subnets: SubnetOption[];
  targetGroups?: TargetGroupOption[];
  vpc?: string;
  checked?: string[];
}) {
  const [vpc, setVpc] = useState(initial ?? (vpcs.find((v) => v.default) ?? vpcs[0])?.id ?? "");
  const own = subnets.filter((s) => s.vpc === vpc);
  const groups = (targetGroups ?? []).filter((t) => !t.vpc || t.vpc === vpc);
  return (
    <>
      <Field label="VPC">
        <select name="vpc" value={vpc} onChange={(e) => setVpc(e.target.value)}>
          {vpcs.map((v) => (
            <option key={v.id} value={v.id}>
              {v.label}
            </option>
          ))}
        </select>
      </Field>
      <fieldset className="checks" key={vpc}>
        <legend>Subnets</legend>
        {own.map((s) => (
          <label key={s.id} className="check">
            <input type="checkbox" name="subnet" value={s.id} defaultChecked={checked ? checked.includes(s.id) : true} /> {s.label} · {s.az}
          </label>
        ))}
      </fieldset>
      {groups.length > 0 && (
        <fieldset className="checks" key={`tg-${vpc}`}>
          <legend>Target groups</legend>
          {groups.map((t) => (
            <label key={t.arn} className="check">
              <input type="checkbox" name="tg" value={t.arn} /> {t.name}
            </label>
          ))}
        </fieldset>
      )}
    </>
  );
}

const RECURRENCE: Rule = { ...PutScheduledUpdateGroupAction.Recurrence, format: undefined, pattern: "^\\S+ \\S+ \\S+ \\S+ \\S+$", hint: "Five cron fields, in UTC: minute hour day month weekday" };

export function ScheduleFields() {
  const [kind, setKind] = useState("once");
  const soon = new Date(Date.now() + 3600_000).toISOString().slice(0, 16);
  return (
    <>
      <Field label="Recurrence">
        <select name="kind" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="once">Once</option>
          <option value="cron">Cron</option>
        </select>
      </Field>
      {kind === "once" ? (
        <Field label="Start time (UTC)" member="StartTime">
          <input name="start" type="datetime-local" required defaultValue={soon} />
        </Field>
      ) : (
        <>
          <Field label="Cron expression" rule={RECURRENCE} member="Recurrence">
            <input name="recurrence" required defaultValue="0 9 * * 1-5" spellCheck={false} />
          </Field>
          <div className="form-row">
            <Field label="Start time (UTC)" member="StartTime">
              <input name="start" type="datetime-local" />
            </Field>
            <Field label="End time (UTC)" member="EndTime">
              <input name="end" type="datetime-local" />
            </Field>
          </div>
        </>
      )}
    </>
  );
}

const ADJUSTMENTS: [string, string][] = [
  ["ChangeInCapacity", "Add or remove instances"],
  ["ExactCapacity", "Set capacity to"],
  ["PercentChangeInCapacity", "Change capacity by percent"],
];
const STEPS: Rule = {
  pattern: "^(\\s*-?\\d*(\\.\\d+)?\\s*:\\s*-?\\d*(\\.\\d+)?\\s*=\\s*-?\\d+\\s*)(\\n\\s*-?\\d*(\\.\\d+)?\\s*:\\s*-?\\d*(\\.\\d+)?\\s*=\\s*-?\\d+\\s*)*$",
  hint: "One step per line: lower:upper=adjustment, relative to the alarm threshold",
};

/** The policies people create most, as tiles: each fills the type, metric, target and a free name. */
const POLICIES: (PresetItem & { type: string; metric?: string; target?: number; name: string })[] = [
  { id: "cpu", label: "CPU", icon: <Cpu size={24} aria-hidden />, type: "TargetTrackingScaling", metric: "ASGAverageCPUUtilization", target: 50, name: "cpu-50", title: "Keep average CPU at 50%" },
  { id: "network-in", label: "Network in", icon: <ArrowDownToLine size={24} aria-hidden />, type: "TargetTrackingScaling", metric: "ASGAverageNetworkIn", target: 10_000_000, name: "network-in" },
  { id: "network-out", label: "Network out", icon: <ArrowUpFromLine size={24} aria-hidden />, type: "TargetTrackingScaling", metric: "ASGAverageNetworkOut", target: 10_000_000, name: "network-out" },
  { id: "target", label: "Target tracking", icon: <Crosshair size={24} aria-hidden />, type: "TargetTrackingScaling", name: "target-tracking", title: "Any predefined metric" },
  { id: "step", label: "Step scaling", icon: <ChartNoAxesColumnIncreasing size={24} aria-hidden />, type: "StepScaling", name: "step-scaling", title: "Steps on a CloudWatch alarm" },
  { id: "simple", label: "Simple scaling", icon: <Plus size={24} aria-hidden />, type: "SimpleScaling", name: "simple-scaling", title: "One adjustment on a CloudWatch alarm" },
];

export function PolicyFields({ taken = [], nameRule }: { taken?: string[]; nameRule?: Rule }) {
  const [preset, setPreset] = useState(POLICIES[0]);
  const type = preset.type;
  return (
    <>
      <PresetGallery presets={POLICIES} chosen={preset.id} choose={setPreset} label="Policy" testId="policy-preset" />
      <div key={preset.id}>
        <Field label="Policy name" rule={nameRule ?? PutScalingPolicy.PolicyName} taken={taken} unique>
          <input name="policy" required autoFocus defaultValue={freeName(preset.name, taken)} />
        </Field>
        <input type="hidden" name="type" value={type} />
        {type === "TargetTrackingScaling" ? (
          <>
            <PolicyTarget metric={preset.metric} target={preset.target} />
            <MoreFields>
              <label className="check">
                <input type="checkbox" name="disableScaleIn" /> Disable scale in
              </label>
            </MoreFields>
          </>
        ) : (
          <>
            <Field label="Adjustment type" rule={PutScalingPolicy.AdjustmentType} member="AdjustmentType">
              <select name="adjustment" defaultValue="ChangeInCapacity">
                {ADJUSTMENTS.map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
            </Field>
            {type === "SimpleScaling" ? (
              <div className="form-row">
                <Field label="Adjustment" rule={{ ...PutScalingPolicy.ScalingAdjustment, required: true }} member="ScalingAdjustment">
                  <input name="amount" type="number" required defaultValue={1} />
                </Field>
                <Field label="Cooldown (seconds)" rule={PutScalingPolicy.Cooldown} member="Cooldown">
                  <input name="cooldown" type="number" min={0} defaultValue={300} />
                </Field>
              </div>
            ) : (
              <Field label="Steps" rule={STEPS} member="StepAdjustments">
                <textarea name="steps" rows={3} required defaultValue={"0:10=1\n10:=2"} spellCheck={false} />
              </Field>
            )}
          </>
        )}
      </div>
    </>
  );
}
