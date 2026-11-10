"use client";

// Fields whose limits depend on each other: a group's desired capacity has
// to sit between its min and max, and a policy's target depends on the
// metric. The rules follow the values as they are typed, so the clamp
// repairs offer the bound that is actually there.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import type { Rule } from "@mws-dashboard/ui";
import { CreateAutoScalingGroup, PutScalingPolicy } from "@mws-dashboard/ui/model/autoscaling";
import { useMemo, useState } from "react";

import { METRICS } from "./metrics";

const whole = (v: string) => (/^\d+$/.test(v.trim()) ? Number(v) : undefined);

/** Min, desired and max, each checked against the others. */
export function GroupSize({ min = 0, desired, max }: { min?: number; desired?: number; max?: number }) {
  const [lo, setLo] = useState(String(min));
  const [hi, setHi] = useState(max === undefined ? "" : String(max));
  const loN = whole(lo);
  const hiN = whole(hi);
  const minRule = useMemo<Rule>(() => ({ ...CreateAutoScalingGroup.MinSize, required: false, min: 0 }), []);
  const maxRule = useMemo<Rule>(
    () => ({
      ...CreateAutoScalingGroup.MaxSize,
      required: false,
      min: loN ?? 0,
    }),
    [loN],
  );
  const desiredRule = useMemo<Rule>(
    () => ({
      ...CreateAutoScalingGroup.DesiredCapacity,
      min: loN ?? 0,
      ...(hiN !== undefined && hiN >= (loN ?? 0) ? { max: hiN } : {}),
    }),
    [loN, hiN],
  );
  return (
    <div className="form-row">
      <Field label="Min" rule={minRule} member="MinSize">
        <input name="min" type="number" min={0} defaultValue={min} onInput={(e) => setLo(e.currentTarget.value)} />
      </Field>
      <Field label="Desired" rule={desiredRule} member="DesiredCapacity">
        <input name="desired" type="number" defaultValue={desired} />
      </Field>
      <Field label="Max" rule={maxRule} member="MaxSize">
        <input name="max" type="number" defaultValue={max} onInput={(e) => setHi(e.currentTarget.value)} />
      </Field>
    </div>
  );
}

const TARGET = PutScalingPolicy.TargetTrackingConfiguration?.fields?.TargetValue ?? { type: "number" as const, required: true };

/** The metric and the value to hold it at: a percentage for CPU, a positive
 * number for the rest. */
export function PolicyTarget() {
  const [metric, setMetric] = useState(METRICS[0][0]);
  const rule = useMemo<Rule>(
    () => ({
      ...TARGET,
      min: 0,
      ...(metric === "ASGAverageCPUUtilization" ? { max: 100 } : {}),
    }),
    [metric],
  );
  return (
    <>
      <Field label="Metric type">
        <select name="metric" value={metric} onChange={(e) => setMetric(e.currentTarget.value)}>
          {METRICS.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Target value" rule={rule} member="TargetTrackingConfiguration.TargetValue">
        <input name="target" type="number" step="any" defaultValue={50} />
      </Field>
    </>
  );
}
