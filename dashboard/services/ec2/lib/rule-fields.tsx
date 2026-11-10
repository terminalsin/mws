"use client";

// An inbound or outbound rule's fields. Client-side because the peer
// field follows its kind: a CIDR block (IPv4 or IPv6, with "anywhere" and
// VPC names as aliases), another security group, or a managed prefix list;
// and the ports go away for "all traffic".

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { Globe, Lock, Network, SquareTerminal } from "lucide-react";
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

/** The rules people add most, as tiles: each fills the protocol, ports and description. */
const COMMON: (PresetItem & { protocol: string; ports?: string })[] = [
  { id: "ssh", label: "SSH", icon: <SquareTerminal size={24} aria-hidden />, protocol: "tcp", ports: "22" },
  { id: "http", label: "HTTP", icon: <Globe size={24} aria-hidden />, protocol: "tcp", ports: "80" },
  { id: "https", label: "HTTPS", icon: <Lock size={24} aria-hidden />, protocol: "tcp", ports: "443" },
  { id: "postgres", label: "PostgreSQL", icon: "brand/postgresql", protocol: "tcp", ports: "5432" },
  { id: "mysql", label: "MySQL", icon: "brand/mysql", protocol: "tcp", ports: "3306" },
  { id: "redis", label: "Redis", icon: "brand/redis", protocol: "tcp", ports: "6379" },
  { id: "mongodb", label: "MongoDB", icon: "brand/mongodb", protocol: "tcp", ports: "27017" },
  { id: "nfs", label: "NFS", icon: "service/AmazonEFS", protocol: "tcp", ports: "2049" },
  { id: "all", label: "All traffic", icon: <Network size={24} aria-hidden />, protocol: "-1" },
];

export function RuleFields({ direction, peers, vpc }: { direction: "ingress" | "egress"; peers: Peers; vpc?: string }) {
  const [protocol, setProtocol] = useState("tcp");
  const [common, setCommon] = useState<(typeof COMMON)[number] | undefined>();
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
      {direction === "ingress" && (
        <PresetGallery
          presets={COMMON}
          chosen={common?.id}
          choose={(c) => {
            setCommon(c);
            setProtocol(c.protocol);
          }}
          label="Common rules"
          size={24}
          testId="rule-preset"
        />
      )}
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
          <input key={common?.id ?? protocol} name="ports" placeholder={protocol === "icmp" ? "-1" : "443 or 8000-8080"} defaultValue={protocol === "icmp" ? "-1" : common?.ports} />
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
        <input key={common?.id} name="description" defaultValue={common?.label} />
      </Field>
    </>
  );
}

/** The security group list's quick "Allow inbound": a common rule's tile, or protocol, ports and a CIDR. */
export function QuickRuleFields({ cidrRule }: { cidrRule: Rule }) {
  const [common, setCommon] = useState<(typeof COMMON)[number] | undefined>();
  return (
    <>
      <PresetGallery presets={COMMON} chosen={common?.id} choose={setCommon} label="Common rules" size={24} testId="rule-preset" />
      <div key={common?.id} className="form-row">
        <Field label="Protocol">
          <select name="protocol" defaultValue={common?.protocol ?? "tcp"}>
            <option>tcp</option>
            <option>udp</option>
            <option value="-1">all</option>
          </select>
        </Field>
        <Field label="Ports" rule={PORTS} member="portRange">
          <input name="ports" placeholder="443 or 8000-8080" defaultValue={common?.ports} />
        </Field>
      </div>
      <Field label="Source CIDR" rule={cidrRule} member="CidrIp">
        <input name="cidr" defaultValue="10.0.0.0/8" required />
      </Field>
    </>
  );
}
