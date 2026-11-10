"use client";

// A volume's size, type, IOPS and throughput. Client-side because the
// limits follow the type: io1/io2 start at 4 GiB, st1/sc1 at 125 GiB,
// only gp3/io1/io2 take IOPS and only gp3 takes throughput.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import type { Rule } from "@mws-dashboard/ui/validation";
import { useMemo, useState } from "react";

import { IOPS, SIZE_LIMITS, THROUGHPUT, VOLUME_SIZE, VOLUME_TYPE, VOLUME_TYPES } from "./rules";

const IOPS_LIMITS: Record<string, [number, number]> = { gp3: [3000, 80000], io1: [100, 64000], io2: [100, 256000] };

export function VolumeFields({
  type: initialType = "gp3",
  size,
  iops,
  throughput,
  minSize,
  optionalSize,
}: {
  type?: string;
  size?: number;
  iops?: number;
  throughput?: number;
  /** A volume only grows; one from a snapshot is at least the snapshot. */
  minSize?: number;
  optionalSize?: boolean;
}) {
  const [type, setType] = useState(initialType);
  const [lo, hi] = SIZE_LIMITS[type] ?? [1, 16384];
  const sizeRule = useMemo<Rule>(() => ({ ...VOLUME_SIZE, min: Math.max(lo, minSize ?? 0), max: hi, required: !optionalSize }), [lo, hi, minSize, optionalSize]);
  const iopsRule = useMemo<Rule>(() => ({ ...IOPS, min: IOPS_LIMITS[type]?.[0], max: IOPS_LIMITS[type]?.[1] }), [type]);
  return (
    <>
      <Field label="Volume type" rule={VOLUME_TYPE} member="VolumeType">
        <select name="type" value={type} onChange={(e) => setType(e.target.value)}>
          {VOLUME_TYPES.map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
      </Field>
      <Field label="Size (GiB)" rule={sizeRule} member="Size">
        <input name="size" type="number" defaultValue={size} placeholder={minSize ? String(minSize) : undefined} required={!optionalSize} />
      </Field>
      {type in IOPS_LIMITS && (
        <Field label="IOPS" rule={iopsRule} member="Iops">
          <input name="iops" type="number" defaultValue={iops ?? (type === "gp3" ? 3000 : undefined)} required={type !== "gp3"} />
        </Field>
      )}
      {type === "gp3" && (
        <Field label="Throughput (MiB/s)" rule={THROUGHPUT} member="Throughput">
          <input name="throughput" type="number" defaultValue={throughput ?? 125} />
        </Field>
      )}
    </>
  );
}
