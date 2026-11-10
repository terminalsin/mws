"use client";

// An inbound or outbound rule's fields. Client-side because the peer
// field follows its kind: a CIDR block (IPv4 or IPv6, with "anywhere" and
// VPC names as aliases), another security group, or a managed prefix list;
// and the ports go away for "all traffic".

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import type { Rule } from "@mws-dashboard/ui/validation";
import { useMemo, useState } from "react";

import { IPV6_CIDR, PORTS, RULE_DESCRIPTION, SOURCE_CIDR } from "./rules";

export interface Peers {
  groups: { id: string; name: string; vpc?: string }[];
  prefixLists: { id: string; name: string }[];
  /** Readable names for CIDR blocks (VPC names). */
  aliases: Record<string, string>;
}

const PROTOCOLS = [
  ["tcp", "TCP"],
  ["udp", "UDP"],
  ["icmp", "ICMP"],
  ["-1", "All traffic"],
];

export function RuleFields({ direction, peers, vpc }: { direction: "ingress" | "egress"; peers: Peers; vpc?: string }) {
  const [protocol, setProtocol] = useState("tcp");
  const [kind, setKind] = useState("cidr");
  const word = direction === "ingress" ? "Source" : "Destination";
  const cidrRule = useMemo<Rule>(
    () => ({
      ...SOURCE_CIDR,
      aliases: { anywhere: "0.0.0.0/0", internet: "0.0.0.0/0", "anywhere-ipv6": "::/0", ...peers.aliases },
    }),
    [peers.aliases],
  );
  const groups = peers.groups.filter((g) => !vpc || !g.vpc || g.vpc === vpc);
  return (
    <>
      <Field label="Protocol">
        <select name="protocol" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
          {PROTOCOLS.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </Field>
      {protocol !== "-1" && (
        <Field label={protocol === "icmp" ? "Type-code" : "Ports"} rule={protocol === "icmp" ? undefined : PORTS} member="portRange">
          <input name="ports" placeholder={protocol === "icmp" ? "-1" : "443 or 8000-8080"} defaultValue={protocol === "icmp" ? "-1" : undefined} />
        </Field>
      )}
      <Field label={`${word} type`}>
        <select name="peer" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="cidr">IPv4 CIDR</option>
          <option value="cidr6">IPv6 CIDR</option>
          <option value="group">Security group</option>
          {peers.prefixLists.length > 0 && <option value="prefixList">Prefix list</option>}
        </select>
      </Field>
      {kind === "cidr" && (
        <Field label={word} rule={cidrRule} member="CidrIp">
          <input name="cidr" defaultValue={direction === "egress" ? "0.0.0.0/0" : "10.0.0.0/8"} required />
        </Field>
      )}
      {kind === "cidr6" && (
        <Field label={word} rule={IPV6_CIDR} member="CidrIpv6">
          <input name="cidr6" defaultValue="::/0" required />
        </Field>
      )}
      {kind === "group" && (
        <Field label={word} member="GroupId">
          <select name="group" required>
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name} · {g.id}
              </option>
            ))}
          </select>
        </Field>
      )}
      {kind === "prefixList" && (
        <Field label={word} member="PrefixListId">
          <select name="prefixList" required>
            {peers.prefixLists.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} · {p.id}
              </option>
            ))}
          </select>
        </Field>
      )}
      <Field label="Description" rule={RULE_DESCRIPTION} member="Description">
        <input name="description" />
      </Field>
    </>
  );
}
