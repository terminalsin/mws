// Network ACL rules: the protocols the VPC console offers, and how a rule
// reads.

import type { NetworkAclEntry } from "@aws-sdk/client-ec2";

export const PROTOCOLS: { value: string; label: string; ports?: boolean }[] = [
  { value: "-1", label: "All traffic" },
  { value: "6", label: "TCP", ports: true },
  { value: "17", label: "UDP", ports: true },
  { value: "1", label: "ICMP" },
  { value: "58", label: "ICMPv6" },
  { value: "custom", label: "Custom protocol" },
];

/** The default rule every ACL ends with. */
export const LAST_RULE = 32767;

export function protocolName(p: string | undefined) {
  return PROTOCOLS.find((x) => x.value === p)?.label ?? `Protocol ${p}`;
}

export function portsOf(e: NetworkAclEntry) {
  if (!e.PortRange) return e.Protocol === "-1" ? "All" : undefined;
  return e.PortRange.From === e.PortRange.To ? String(e.PortRange.From) : `${e.PortRange.From}-${e.PortRange.To}`;
}
