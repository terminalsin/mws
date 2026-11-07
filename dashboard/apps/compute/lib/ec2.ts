import "server-only";

import { DescribeInstancesCommand, type SecurityGroupRule } from "@aws-sdk/client-ec2";
import { collect } from "@mws-dashboard/aws";
import type { Tone } from "@mws-dashboard/ui";

import { ec2 } from "./clients";

export const STATE_TONE: Record<string, Tone> = {
  running: "good",
  pending: "warn",
  stopping: "warn",
  "shutting-down": "warn",
  stopped: "neutral",
  terminated: "bad",
};

export async function listInstances() {
  const client = await ec2();
  const reservations = await collect(
    (NextToken) => client.send(new DescribeInstancesCommand({ NextToken })),
    (r) => r.Reservations,
    (r) => r.NextToken,
  );
  return reservations.flatMap((r) => r.Instances ?? []);
}

const SENSITIVE = new Set([22, 3389, 3306, 5432, 6379, 27017, 9200, 11211]);

/** A rule as people say it ("443 from anywhere"), and whether it exposes an admin or database port to the internet. */
export function describeRule(r: SecurityGroupRule) {
  const ports = r.IpProtocol === "-1" ? "all" : r.FromPort === r.ToPort ? `${r.FromPort}` : `${r.FromPort}-${r.ToPort}`;
  const open = r.CidrIpv4 === "0.0.0.0/0" || r.CidrIpv6 === "::/0";
  const source = open ? "anywhere" : (r.CidrIpv4 ?? r.CidrIpv6 ?? r.ReferencedGroupInfo?.GroupId ?? r.PrefixListId ?? "");
  const exposed =
    open && (r.IpProtocol === "-1" || [...SENSITIVE].some((p) => (r.FromPort ?? 0) <= p && p <= (r.ToPort ?? 65535)));
  return { ports, source, exposed, text: `${r.IpProtocol === "-1" ? "" : `${r.IpProtocol} `}${ports} ← ${source}` };
}
