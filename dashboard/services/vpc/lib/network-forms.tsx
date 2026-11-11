"use client";

// Create and edit forms whose fields follow other choices: a route's
// destination can be IPv4, IPv6 or a prefix list; an endpoint's network
// settings follow its type and VPC; a peering's accepter is a VPC here or an
// ID elsewhere; an ACL rule's ports follow its protocol; a NAT gateway needs
// an Elastic IP only when it is public.

import { AutoPick } from "@mws-dashboard/ui/client";
import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import { Section, Sections } from "@mws-dashboard/ui/sections";
import type { Rule } from "@mws-dashboard/ui/validation";
import { CreateNetworkAclEntry, CreateRoute, CreateVpcEndpoint } from "@mws-dashboard/ui/model/ec2";
import { ArrowLeftRight, Asterisk, Globe, Lock, Monitor, Terminal } from "lucide-react";
import { useMemo, useState } from "react";

import { PROTOCOLS } from "./acl";
import { KNOWN_SERVICES, serviceKey } from "./endpoint-services";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

const IPV4: Rule = { ...CreateRoute.DestinationCidrBlock, format: "cidr" };
const OTHER: Rule = {
  pattern: "^(pl-[0-9a-f]{8,17}|[0-9a-fA-F:]+/\\d{1,3})$",
  hint: "An IPv4 or IPv6 CIDR, or a prefix list ID",
};
export const TARGET: Rule = {
  pattern: "^(igw|vgw|nat|pcx|tgw|eni|i|eigw|cagw|vpce)-[0-9a-f]{8,17}$",
  hint: "A gateway, NAT, peering, transit gateway, interface, instance or endpoint ID",
};

export function RouteFields({ taken, targets, destination, target }: { taken: string[]; targets: string[]; destination?: string; target?: string }) {
  const [value, setValue] = useState(destination ?? "0.0.0.0/0");
  const rule = /^pl-|:/.test(value) ? OTHER : IPV4;
  const list = useMemo(() => `targets-${Math.random().toString(36).slice(2)}`, []);
  return (
    <>
      {destination ? (
        <input type="hidden" name="destination" value={destination} />
      ) : (
        <Field label="Destination" rule={rule} member="DestinationCidrBlock" taken={taken}>
          <input name="destination" required value={value} onChange={(e) => setValue(e.target.value)} spellCheck={false} />
        </Field>
      )}
      <Field label="Target" rule={TARGET} known={targets}>
        <input name="target" required list={list} defaultValue={target ?? targets[0]} spellCheck={false} autoFocus={!!destination} />
      </Field>
      <datalist id={list}>
        {targets.map((x) => (
          <option key={x} value={x} />
        ))}
      </datalist>
    </>
  );
}

export interface Choice {
  id: string;
  label: string;
}

export interface NetworkChoice extends Choice {
  tables: Choice[];
  subnets: (Choice & { az: string })[];
  groups: Choice[];
}

export interface ServiceChoice {
  name: string;
  types: string[];
  privateDns: boolean;
}

function Checks({ name, legend, items, checked }: { name: string; legend: string; items: Choice[]; checked?: string[] }) {
  if (!items.length) return null;
  return (
    <fieldset className="checks">
      <legend>{legend}</legend>
      {items.map((x) => (
        <label key={x.id} className="check">
          <input type="checkbox" name={name} value={x.id} defaultChecked={checked?.includes(x.id)} /> {x.label}
        </label>
      ))}
    </fieldset>
  );
}

export function EndpointFields({ services, vpcs }: { services: ServiceChoice[]; vpcs: NetworkChoice[] }) {
  const [service, setService] = useState(services.find((s) => s.name.endsWith(".s3"))?.name ?? services[0]?.name ?? "");
  const offered = services.find((s) => s.name === service)?.types ?? ["Gateway"];
  const [picked, setPicked] = useState<string | null>(null);
  const type = picked && offered.includes(picked) ? picked : offered[0];
  const [vpcId, setVpcId] = useState(vpcs[0]?.id ?? "");
  const vpc = vpcs.find((v) => v.id === vpcId);
  // The well-known services this Region offers, as logo tiles; the select
  // below still lists every service.
  const tiles = useMemo(
    () =>
      KNOWN_SERVICES.flatMap((k) => {
        const s = services.find((x) => serviceKey(x.name) === k.key);
        const gateway = s?.types.includes("Gateway");
        return s
          ? [
              {
                id: s.name,
                label: k.label,
                icon: k.icon,
                title: gateway ? `${s.name} · gateway endpoint, no charge` : s.name,
                found: gateway,
              } satisfies PresetItem,
            ]
          : [];
      }),
    [services],
  );
  return (
    <Sections testId="endpoint">
      <Section id="service" label="Service" summary={tiles.find((t) => t.id === service)?.label}>
        {tiles.length > 0 && <PresetGallery presets={tiles} chosen={service} choose={(t) => setService(t.id)} label="Service" size={24} testId="endpoint-service" />}
        <Field label="Service" rule={CreateVpcEndpoint.ServiceName} member="ServiceName">
          <select name="service" required value={service} onChange={(e) => setService(e.target.value)}>
            {services.map((s) => (
              <option key={s.name} value={s.name}>
                {s.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Type" rule={CreateVpcEndpoint.VpcEndpointType} member="VpcEndpointType">
          <select name="type" value={type} onChange={(e) => setPicked(e.target.value)}>
            {offered.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </Field>
      </Section>
      <Section id="network" label="Network">
        <Field label="VPC" rule={CreateVpcEndpoint.VpcId} member="VpcId">
          <select name="vpc" required value={vpcId} onChange={(e) => setVpcId(e.target.value)}>
            {vpcs.map((v) => (
              <option key={v.id} value={v.id}>
                {v.label}
              </option>
            ))}
          </select>
        </Field>
        {vpc && type === "Gateway" && <Checks key={`t-${vpc.id}`} name="table" legend="Route tables" items={vpc.tables} />}
        {vpc && type !== "Gateway" && (
          <>
            <Checks
              key={`s-${vpc.id}`}
              name="subnet"
              legend="Subnets"
              items={vpc.subnets.map((s) => ({
                id: s.id,
                label: `${s.label} · ${s.az}`,
              }))}
            />
            <Checks key={`g-${vpc.id}`} name="group" legend="Security groups" items={vpc.groups} checked={vpc.groups.filter((g) => g.label === "default").map((g) => g.id)} />
            {services.find((s) => s.name === service)?.privateDns && (
              <label className="check">
                <input type="checkbox" name="privateDns" defaultChecked /> Enable private DNS name
              </label>
            )}
          </>
        )}
      </Section>
      <Section id="name" label="Name and policy">
        <Field label="Name" rule={{ maxLength: 256 }}>
          <input name="name" />
        </Field>
        <MoreFields>
          <Field
            label="Policy"
            rule={{
              ...CreateVpcEndpoint.PolicyDocument,
              format: "policy",
              required: false,
            }}
            member="PolicyDocument"
            hint="Full access when empty"
          >
            <textarea name="policy" rows={5} spellCheck={false} />
          </Field>
        </MoreFields>
      </Section>
    </Sections>
  );
}

export function EndpointNetworkFields({
  type,
  vpc,
  tables,
  subnets,
  groups,
  privateDns,
}: {
  type: string;
  vpc: NetworkChoice;
  tables: string[];
  subnets: string[];
  groups: string[];
  privateDns: boolean;
}) {
  if (type === "Gateway") return <Checks name="table" legend="Route tables" items={vpc.tables} checked={tables} />;
  return (
    <>
      <Checks
        name="subnet"
        legend="Subnets"
        items={vpc.subnets.map((s) => ({
          id: s.id,
          label: `${s.label} · ${s.az}`,
        }))}
        checked={subnets}
      />
      <Checks name="group" legend="Security groups" items={vpc.groups} checked={groups} />
      <label className="check">
        <input type="checkbox" name="privateDns" defaultChecked={privateDns} /> Enable private DNS name
      </label>
    </>
  );
}

const ACCOUNT: Rule = { pattern: "^\\d{12}$", hint: "A 12-digit account ID" };
const VPC_ID: Rule = { pattern: "^vpc-[0-9a-f]{8,17}$", hint: "A VPC ID" };

export function PeeringFields({ vpcs, regions, region }: { vpcs: Choice[]; regions: string[]; region: string }) {
  const [where, setWhere] = useState("here");
  const [vpcId, setVpcId] = useState(vpcs[0]?.id ?? "");
  return (
    <>
      <Field label="Name" rule={{ maxLength: 256 }}>
        <input name="name" />
      </Field>
      <Field label="Requester VPC" member="VpcId">
        <select name="vpc" required value={vpcId} onChange={(e) => setVpcId(e.target.value)}>
          {vpcs.map((v) => (
            <option key={v.id} value={v.id}>
              {v.label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Accepter">
        <select name="where" value={where} onChange={(e) => setWhere(e.target.value)}>
          <option value="here">My account, this Region</option>
          <option value="elsewhere">Another account or Region</option>
        </select>
      </Field>
      {where === "here" ? (
        <Field label="Accepter VPC" member="PeerVpcId">
          <select name="peer" required defaultValue={vpcs.find((v) => v.id !== vpcId)?.id}>
            {vpcs
              .filter((v) => v.id !== vpcId)
              .map((v) => (
                <option key={v.id} value={v.id}>
                  {v.label}
                </option>
              ))}
          </select>
        </Field>
      ) : (
        <>
          <div className="form-row">
            <Field label="Account ID" rule={ACCOUNT} member="PeerOwnerId" hint="This account when empty">
              <input name="account" inputMode="numeric" />
            </Field>
            <Field label="Region" member="PeerRegion" known={regions}>
              <select name="region" defaultValue={region}>
                {regions.map((r) => (
                  <option key={r}>{r}</option>
                ))}
              </select>
            </Field>
          </div>
          <Field label="Accepter VPC ID" rule={VPC_ID} member="PeerVpcId">
            <ResourcePicker kind="vpc" name="peer" required />
          </Field>
        </>
      )}
    </>
  );
}

const RULE_NUMBER: Rule = {
  ...CreateNetworkAclEntry.RuleNumber,
  min: 1,
  max: 32766,
};

// Common rules, as tiles: each sets the protocol and ports.
interface AclPreset extends PresetItem {
  protocol: string;
  ports?: string;
}
const ACL_PRESETS: AclPreset[] = [
  {
    id: "https",
    label: "HTTPS",
    protocol: "6",
    ports: "443",
    icon: <Lock size={22} aria-hidden />,
  },
  {
    id: "http",
    label: "HTTP",
    protocol: "6",
    ports: "80",
    icon: <Globe size={22} aria-hidden />,
  },
  {
    id: "ssh",
    label: "SSH",
    protocol: "6",
    ports: "22",
    icon: <Terminal size={22} aria-hidden />,
  },
  {
    id: "rdp",
    label: "RDP",
    protocol: "6",
    ports: "3389",
    icon: <Monitor size={22} aria-hidden />,
  },
  {
    id: "ephemeral",
    label: "Ephemeral",
    protocol: "6",
    ports: "1024-65535",
    icon: <ArrowLeftRight size={22} aria-hidden />,
    title: "Return traffic: TCP 1024-65535",
  },
  {
    id: "all",
    label: "All traffic",
    protocol: "-1",
    icon: <Asterisk size={22} aria-hidden />,
  },
];

export function AclEntryFields({
  taken,
  entry,
}: {
  taken: string[];
  entry?: {
    number: number;
    egress: boolean;
    protocol: string;
    ports?: string;
    cidr: string;
    action: string;
  };
}) {
  const known = PROTOCOLS.some((p) => p.value === entry?.protocol);
  const [preset, setPreset] = useState<AclPreset | undefined>(entry ? undefined : ACL_PRESETS[0]);
  const [protocol, setProtocol] = useState(entry ? (known ? entry.protocol : "custom") : "6");
  const pick = (p: AclPreset) => {
    setPreset(p);
    setProtocol(p.protocol);
  };
  const ports = PROTOCOLS.find((p) => p.value === protocol)?.ports || protocol === "custom";
  const next = useMemo(() => {
    for (let n = 100; n < 32766; n += 100) if (!taken.includes(String(n))) return n;
    return 1;
  }, [taken]);
  return (
    <>
      {!entry && (
        <div className="form-row">
          <Field label="Rule number" rule={RULE_NUMBER} member="RuleNumber" taken={taken}>
            <input name="number" type="number" required defaultValue={next} />
          </Field>
          <Field label="Direction">
            <select name="direction" defaultValue="inbound">
              <option value="inbound">Inbound</option>
              <option value="outbound">Outbound</option>
            </select>
          </Field>
        </div>
      )}
      {!entry && (
        <PresetGallery presets={ACL_PRESETS} chosen={preset && preset.protocol === protocol ? preset.id : undefined} choose={pick} label="Rule" size={22} testId="acl-preset" />
      )}
      <div className="form-row" key={preset?.id}>
        <Field label="Type" member="Protocol">
          <select name="protocol" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            {PROTOCOLS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
        </Field>
        {protocol === "custom" && (
          <Field label="Protocol number" rule={{ type: "integer", min: 0, max: 255, required: true }} member="Protocol">
            <input name="protocolNumber" type="number" required defaultValue={known ? undefined : entry?.protocol} />
          </Field>
        )}
        {ports && (
          <Field label="Port range" format="ports" member="PortRange">
            <input name="ports" required={protocol !== "custom"} defaultValue={entry?.ports ?? preset?.ports ?? "443"} spellCheck={false} />
          </Field>
        )}
      </div>
      <div className="form-row">
        <Field label={entry?.egress ? "Destination" : "Source"} format="cidr" member="CidrBlock">
          <input name="cidr" required defaultValue={entry?.cidr ?? "0.0.0.0/0"} spellCheck={false} />
        </Field>
        <Field label="Allow/Deny" rule={CreateNetworkAclEntry.RuleAction} member="RuleAction">
          <select name="action" defaultValue={entry?.action ?? "allow"}>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
        </Field>
      </div>
    </>
  );
}

export function NatFields({ subnets, addresses, subnet }: { subnets: (Choice & { public: boolean })[]; addresses: Choice[]; subnet?: string }) {
  const [type, setType] = useState("public");
  return (
    <>
      <Field label="Name" rule={{ maxLength: 256 }}>
        <input name="name" />
      </Field>
      <Field label="Subnet" member="SubnetId">
        <select name="subnet" required defaultValue={subnet ?? subnets.find((s) => s.public)?.id}>
          {subnets.map((s) => (
            <option key={s.id} value={s.id}>
              {s.label}
              {s.public ? " · public" : ""}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Connectivity type" member="ConnectivityType">
        <select name="connectivity" value={type} onChange={(e) => setType(e.target.value)}>
          <option value="public">Public</option>
          <option value="private">Private</option>
        </select>
      </Field>
      {type === "public" && (
        <AutoPick name="eip" label="Elastic IP" creates="Allocate a new Elastic IP" options={addresses.map((a) => ({ value: a.id, label: a.label }))} testId="nat-eip" />
      )}
    </>
  );
}
