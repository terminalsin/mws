"use client";

// A node group's sizes, checked against each other as they are typed:
// desired sits between min and max, and min never passes max. Each bound
// is the other field's current value, so the repair clamps to it.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { mergeRules, type Rule } from "@mws-dashboard/ui/validation";
import { useState } from "react";

type Sizes = { minSize?: Rule; desiredSize?: Rule; maxSize?: Rule };

const num = (v: string) => (v.trim() === "" || Number.isNaN(Number(v)) ? undefined : Number(v));

export function Scaling({
  rules,
  names,
  defaults,
}: {
  /** The model's scalingConfig members. */
  rules: Sizes;
  /** Form field names; leave out `min` when the form derives it. */
  names: { min?: string; desired: string; max: string };
  defaults: { min?: number; desired?: number; max?: number };
}) {
  const [min, setMin] = useState(String(defaults.min ?? ""));
  const [desired, setDesired] = useState(String(defaults.desired ?? ""));
  const [max, setMax] = useState(String(defaults.max ?? ""));
  const lo = names.min ? num(min) : undefined;
  const hi = num(max);
  return (
    <div className="form-row">
      {names.min && (
        <Field label="Min" member="scalingConfig.minSize" rule={mergeRules(rules.minSize, hi !== undefined && { max: hi })}>
          <input name={names.min} type="number" value={min} onChange={(e) => setMin(e.target.value)} />
        </Field>
      )}
      <Field label={names.min ? "Desired" : "Desired size"} member="scalingConfig.desiredSize" rule={mergeRules(rules.desiredSize, lo !== undefined && { min: lo }, hi !== undefined && { max: hi })}>
        <input name={names.desired} type="number" required value={desired} onChange={(e) => setDesired(e.target.value)} />
      </Field>
      <Field label={names.min ? "Max" : "Max size"} member="scalingConfig.maxSize" rule={rules.maxSize}>
        <input name={names.max} type="number" required value={max} onChange={(e) => setMax(e.target.value)} />
      </Field>
    </div>
  );
}
