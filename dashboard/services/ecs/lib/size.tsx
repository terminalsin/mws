"use client";

// A Fargate task size: the memory field's allowed values follow the chosen
// CPU, so a size Fargate does not offer is flagged with the nearest ones.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { useMemo, useState } from "react";

import { FARGATE_MEMORY, memoryHint } from "./rules";

export function FargateSize() {
  const [cpu, setCpu] = useState("256");
  const memory = useMemo(() => ({ enum: FARGATE_MEMORY[cpu] }), [cpu]);
  return (
    <div className="form-row">
      <FieldShell label="CPU">
        <select name="cpu" value={cpu} onChange={(e) => setCpu(e.target.value)}>
          {Object.keys(FARGATE_MEMORY).map((c) => (
            <option key={c} value={c}>
              {Number(c) / 1024} vCPU
            </option>
          ))}
        </select>
      </FieldShell>
      <FieldShell label="Memory (MiB)" hint={memoryHint(cpu)} rule={memory}>
        <input name="memory" type="number" defaultValue={512} min={512} />
      </FieldShell>
    </div>
  );
}
