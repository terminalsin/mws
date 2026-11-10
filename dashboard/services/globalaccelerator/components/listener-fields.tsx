"use client";

import { FieldShell } from "@mws-dashboard/ui/fields";
import { valid, type Rule } from "@mws-dashboard/ui/validation";
import { useState } from "react";

type Protocol = "TCP" | "UDP";

/** Ports and protocol of a new listener: the ports field knows which ranges
 * the accelerator's listeners already use for the chosen protocol, and
 * offers the next free ones. */
export function ListenerFields({ rule, used }: { rule: Rule; used: Record<Protocol, string[]> }) {
  const [protocol, setProtocol] = useState<Protocol>("TCP");
  const [first] = useState(() => ["80", "443"].find((p) => valid(p, { ...rule, taken: used.TCP })) ?? "");
  return (
    <div className="form-row">
      <FieldShell label="Ports" rule={rule} taken={used[protocol]}>
        <input name="ports" required defaultValue={first} placeholder="80, 443 or 8000-8100" />
      </FieldShell>
      <FieldShell label="Protocol">
        <select name="protocol" value={protocol} onChange={(e) => setProtocol(e.target.value as Protocol)}>
          <option>TCP</option>
          <option>UDP</option>
        </select>
      </FieldShell>
    </div>
  );
}
