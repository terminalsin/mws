"use client";

// The VPC and subnet create forms' fields. Client-side because the CIDR's
// rule follows the other choices: a subnet must fit the VPC picked and
// stay clear of that VPC's subnets, and "VPC and more" needs room for four
// subnets. The subnet CIDR starts at the VPC's first free block, and moves
// on when the VPC changes or the block gets used.

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { freeBlocks, type Rule } from "@mws-dashboard/ui/validation";
import { CreateSubnet, CreateVpc } from "@mws-dashboard/ui/model/ec2";
import { useMemo, useState } from "react";

/** AWS allows /16 to /28 for VPCs and subnets. */
const NETMASK: [number, number] = [16, 28];
const NAME: Rule = { maxLength: 256 };

const prefixOf = (cidr: string) => Number(cidr.split("/")[1]);

/** The first free block for a new subnet: a sixteenth of the VPC (a /20 in
 * a /16), or the largest that still fits. */
function firstFree(cidrs: string[], subnets: string[]) {
  const bits = Math.min(NETMASK[1], Math.max(...cidrs.map(prefixOf)) + 4);
  for (let size = bits; size <= NETMASK[1]; size++) {
    const [free] = freeBlocks(size, { within: cidrs, avoid: subnets }, 1);
    if (free) return free;
  }
  return "";
}

export interface VpcChoice {
  id: string;
  label: string;
  cidrs: string[];
  subnets: string[];
}

export function SubnetFields({ vpcs, zones, vpc: fixed }: { vpcs: VpcChoice[]; zones: string[]; vpc?: string }) {
  const [vpcId, setVpcId] = useState(fixed ?? vpcs[0]?.id ?? "");
  const vpc = vpcs.find((v) => v.id === vpcId);
  const [typed, setTyped] = useState<string | null>(null);
  const suggested = useMemo(() => (vpc ? firstFree(vpc.cidrs, vpc.subnets) : ""), [vpc]);
  const [seen, setSeen] = useState(suggested);
  if (seen !== suggested) {
    setSeen(suggested);
    setTyped(null);
  }
  const rule = useMemo<Rule>(
    () => ({ ...CreateSubnet.CidrBlock, format: "cidr", cidr: { prefix: NETMASK, within: vpc?.cidrs, avoid: vpc?.subnets } }),
    [vpc],
  );
  return (
    <>
      {fixed ? (
        <input type="hidden" name="vpc" value={fixed} />
      ) : (
        <Field label="VPC" rule={CreateSubnet.VpcId} member="VpcId">
          <select name="vpc" required value={vpcId} onChange={(e) => setVpcId(e.target.value)}>
            {vpcs.map((v) => (
              <option key={v.id} value={v.id}>
                {v.label} · {v.cidrs.join(", ")}
              </option>
            ))}
          </select>
        </Field>
      )}
      <Field label="Name" rule={NAME}>
        <input name="name" />
      </Field>
      <div className="form-row">
        <Field label="IPv4 CIDR" rule={rule} member="CidrBlock">
          <input name="cidr" required value={typed ?? suggested} onChange={(e) => setTyped(e.target.value)} spellCheck={false} />
        </Field>
        <Field label="Availability Zone" member="AvailabilityZone">
          <select name="az" defaultValue="">
            <option value="">No preference</option>
            {zones.map((z) => (
              <option key={z}>{z}</option>
            ))}
          </select>
        </Field>
      </div>
    </>
  );
}

export function VpcFields({ used }: { used: string[] }) {
  const [layout, setLayout] = useState("public-private");
  // A /16 in 10.0.0.0/8 that no VPC uses yet, so peering stays possible.
  const suggested = useMemo(() => freeBlocks(16, { within: ["10.0.0.0/8"], avoid: used }, 1)[0] ?? "10.0.0.0/16", [used]);
  // Four subnets need at least /26 (four /28s).
  const rule = useMemo<Rule>(
    () => ({ ...CreateVpc.CidrBlock, format: "cidr", cidr: { prefix: [NETMASK[0], layout === "vpc" ? NETMASK[1] : 26] } }),
    [layout],
  );
  return (
    <>
      <Field label="Name" rule={NAME}>
        <input name="name" autoFocus />
      </Field>
      <Field label="IPv4 CIDR" rule={rule} member="CidrBlock">
        <input name="cidr" required defaultValue={suggested} spellCheck={false} />
      </Field>
      <Field label="Resources">
        <select name="layout" value={layout} onChange={(e) => setLayout(e.target.value)}>
          <option value="public-private">VPC and more: public and private subnets in 2 zones</option>
          <option value="vpc">VPC only</option>
        </select>
      </Field>
    </>
  );
}
