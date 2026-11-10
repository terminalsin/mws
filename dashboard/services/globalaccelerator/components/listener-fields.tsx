"use client";

import { FieldShell } from "@mws-dashboard/ui/fields";
import { valid, type Rule } from "@mws-dashboard/ui/validation";
import { useState } from "react";

type Protocol = "TCP" | "UDP";

/** Ports and protocol of a listener: the ports field knows which ranges the
 * accelerator's other listeners already use for the chosen protocol, and
 * offers the next free ones. */
export function ListenerFields({
  rule,
  used,
  defaults,
}: {
  rule: Rule;
  used: Record<Protocol, string[]>;
  defaults?: { ports: string; protocol: Protocol; affinity?: string };
}) {
  const [protocol, setProtocol] = useState<Protocol>(defaults?.protocol ?? "TCP");
  const [first] = useState(() => defaults?.ports ?? ["80", "443"].find((p) => valid(p, { ...rule, taken: used.TCP })) ?? "");
  return (
    <>
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
      <FieldShell label="Client affinity" member="ClientAffinity">
        <select name="affinity" defaultValue={defaults?.affinity ?? "NONE"}>
          <option value="NONE">None</option>
          <option value="SOURCE_IP">Source IP</option>
        </select>
      </FieldShell>
    </>
  );
}

/** An endpoint group's Region and endpoints: the suggestions follow the
 * chosen Region, since endpoints must be in the group's Region. */
export function EndpointGroupFields({
  regions,
  candidates,
  initial,
  rule,
}: {
  regions: string[];
  candidates: Record<string, { id: string; label: string }[]>;
  initial: string;
  rule: Rule;
}) {
  const [region, setRegion] = useState(regions.includes(initial) ? initial : regions[0]);
  const here = candidates[region] ?? [];
  return (
    <>
      <FieldShell label="Region" member="EndpointGroupRegion">
        <select name="region" value={region} onChange={(e) => setRegion(e.target.value)}>
          {regions.map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
      </FieldShell>
      <FieldShell label="Endpoints (one per line, id or id=weight)" rule={rule} known={here.map((c) => c.id)} member="EndpointId">
        <textarea name="endpoint" rows={2} placeholder={here[0]?.id ?? "Load balancer, instance or Elastic IP"} />
      </FieldShell>
    </>
  );
}
