import {
  DescribeAddressesAttributeCommand,
  DescribeAvailabilityZonesCommand,
  DescribeInstancesCommand,
  DescribeNetworkInterfacesCommand,
  DescribeRegionsCommand,
  DescribeVpcEndpointServicesCommand,
  type RouteTable,
  type Subnet,
  type Vpc,
} from "@aws-sdk/client-ec2";
import { all, load, region } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { AllocateAddress } from "@mws-dashboard/ui/model/ec2";
import { Ban, Check, Globe, Link2, Plus, ShieldAlert, Star, Trash2, Unlink, X } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { ec2, ICONS, nameTag, STATE_TONE } from "../../lib/clients";
import { knownService, serviceKey } from "../../lib/endpoint-services";
import { SubnetFields, VpcFields } from "../../lib/forms";
import { EndpointFields, NatFields, PeeringFields, type NetworkChoice } from "../../lib/network-forms";
import { choices, cidrsOf, isPublic, label, listAcls, listAddresses, listEndpoints, listGroups, listIgws, listNats, listPeerings, routeTarget } from "../../lib/vpc";
import {
  attachInternetGateway,
  createDefaultVpc,
  createInternetGateway,
  createNatGateway,
  createRouteTable,
  createSubnet,
  createVpc,
  deleteInternetGateway,
  deleteNatGateway,
  deleteRouteTable,
  deleteSubnet,
  deleteVpc,
  detachInternetGateway,
} from "./actions";
import {
  acceptPeering,
  allocateAddress,
  associateAddress,
  createAcl,
  createEndpoint,
  createPeering,
  deleteEndpoint,
  deletePeering,
  disassociateAddress,
  rejectPeering,
  releaseAddress,
  setReverseDns,
} from "./network-actions";

export interface Net {
  vpcs: Vpc[];
  subnets: Subnet[];
  tables: RouteTable[];
}

export type Tab = (net: Net) => Promise<{ body: ReactNode; actions?: ReactNode }>;

const NAME = { maxLength: 256 };

function VpcSelect({ vpcs, name = "vpc", label: text = "VPC", optional, defaultValue }: { vpcs: Vpc[]; name?: string; label?: string; optional?: string; defaultValue?: string }) {
  return (
    <Field label={text} member="VpcId">
      <select name={name} required={!optional} defaultValue={defaultValue}>
        {optional && <option value="">{optional}</option>}
        {vpcs.map((v) => (
          <option key={v.VpcId} value={v.VpcId}>
            {label(v, v.VpcId)} · {v.CidrBlock}
          </option>
        ))}
      </select>
    </Field>
  );
}

export function CreateVpcSheet({ used, names }: { used: string[]; names?: string[] }) {
  return (
    <Sheet title="Create VPC" label="Create VPC" testId="create-vpc">
      <ActionForm action={createVpc} submit="Create VPC" testId="create-vpc">
        <VpcFields used={used} names={names} />
      </ActionForm>
    </Sheet>
  );
}

export function CreateRouteTableSheet({ vpcs, vpc }: { vpcs: Vpc[]; vpc?: string }) {
  return (
    <Sheet title="Create route table" label="Create route table" icon={<AwsIcon icon={ICONS.routeTable} size={18} />} testId="create-route-table">
      <ActionForm action={createRouteTable} submit="Create route table" testId="create-route-table">
        <Field label="Name" rule={NAME}>
          <input name="name" autoFocus />
        </Field>
        {vpc ? <input type="hidden" name="vpc" value={vpc} /> : <VpcSelect vpcs={vpcs} />}
      </ActionForm>
    </Sheet>
  );
}

export async function natSheet(subnets: Subnet[], tables: RouteTable[], subnet?: string) {
  const addresses = await listAddresses().catch(() => []);
  return (
    <Sheet title="Create NAT gateway" label="Create NAT gateway" icon={<AwsIcon icon={ICONS.nat} size={18} />} testId="create-nat">
      <ActionForm action={createNatGateway} submit="Create NAT gateway" testId="create-nat">
        <NatFields
          subnet={subnet}
          subnets={subnets.map((s) => ({ id: s.SubnetId!, label: `${label(s, s.SubnetId)} · ${s.AvailabilityZone}`, public: isPublic(s, tables) }))}
          addresses={addresses.filter((a) => !a.AssociationId).map((a) => ({ id: a.AllocationId!, label: `${a.PublicIp}${nameTag(a) ? ` · ${nameTag(a)}` : ""}` }))}
        />
      </ActionForm>
    </Sheet>
  );
}

export function DeleteNat({ id, hasEip }: { id: string; hasEip: boolean }) {
  return (
    <Sheet title={`Delete ${id}`} label={`Delete ${id}`} icon={<Trash2 size={15} />} testId={`delete-nat-${id}`}>
      <ActionForm action={deleteNatGateway.bind(null, id)} submit="Delete NAT gateway" tone="danger" testId={`delete-nat-${id}`}>
        {hasEip && (
          <label className="check">
            <input type="checkbox" name="release" defaultChecked /> Release the Elastic IP address
          </label>
        )}
      </ActionForm>
    </Sheet>
  );
}

/** What deleting a VPC also deletes, for its confirmation. */
export function deleteVpcConfirm(name: string) {
  return `Delete ${name}? Its subnets, route tables, security groups, network ACLs, endpoints, peering connections and internet gateways are deleted with it.`;
}

export const vpcsTab: Tab = async ({ vpcs, subnets, tables }) => {
  const used = vpcs.flatMap(cidrsOf);
  const names = vpcs.map((v) => nameTag(v)).filter((n): n is string => !!n);
  return {
    actions: (
      <>
        {!vpcs.some((v) => v.IsDefault) && <ActionForm action={createDefaultVpc} submit="Create default VPC" icon={<Star size={16} />} confirm="Create a default VPC with a default subnet in every Availability Zone?" />}
        <CreateVpcSheet used={used} names={names} />
      </>
    ),
    body: (
      <List
        label="VPCs"
        empty={<Empty icon={ICONS.vpc} action={<CreateVpcSheet used={used} names={names} />} />}
        rows={vpcs.map((v) => {
          const own = subnets.filter((s) => s.VpcId === v.VpcId);
          const pub = own.filter((s) => isPublic(s, tables)).length;
          const name = label(v, v.VpcId);
          return {
            key: v.VpcId!,
            icon: <AwsIcon icon={ICONS.vpc} size={24} />,
            title: name,
            subtitle: `${cidrsOf(v).join(", ")}${nameTag(v) ? ` · ${v.VpcId}` : ""}`,
            href: `/vpc/${v.VpcId}`,
            meta: (
              <>
                {v.IsDefault && <Pill tone="info">Default</Pill>}
                {own.length > 0 && <span title={`${pub} public, ${own.length - pub} private`}>{own.length} subnets</span>}
                <Status tone={STATE_TONE(v.State)}>{v.State}</Status>
              </>
            ),
            actions: v.IsDefault ? undefined : (
              <ActionForm action={deleteVpc.bind(null, v.VpcId!)} submit={`Delete ${v.VpcId}`} icon={<Trash2 size={15} />} tone="danger" confirm={deleteVpcConfirm(name)} />
            ),
          };
        })}
      />
    ),
  };
};

export const subnetsTab: Tab = async ({ vpcs, subnets, tables }) => {
  const zones = await load(async () => (await (await ec2()).send(new DescribeAvailabilityZonesCommand({}))).AvailabilityZones ?? []);
  const vpcName = (id: string | undefined) => label(vpcs.find((x) => x.VpcId === id), id);
  return {
    actions: (
      <Sheet title="Create subnet" label="Create subnet" testId="create-subnet">
        <ActionForm action={createSubnet} submit="Create subnet" testId="create-subnet">
          <SubnetFields vpcs={choices(vpcs, subnets)} zones={zones.ok ? zones.value.map((z) => z.ZoneName!) : []} />
        </ActionForm>
      </Sheet>
    ),
    body: (
      <Curated
        label="Subnets"
        sections={[
          { id: "public", title: "Public", items: subnets.filter((s) => isPublic(s, tables)) },
          { id: "private", title: "Private", items: subnets.filter((s) => !isPublic(s, tables)) },
        ]}
        empty={<Empty icon={ICONS.privateSubnet} />}
        row={(s) => ({
          key: s.SubnetId!,
          icon: <AwsIcon icon={isPublic(s, tables) ? ICONS.publicSubnet : ICONS.privateSubnet} size={24} />,
          title: label(s, s.SubnetId),
          subtitle: `${[s.CidrBlock, ...(s.Ipv6CidrBlockAssociationSet ?? []).map((a) => a.Ipv6CidrBlock)].filter(Boolean).join(", ")} · ${vpcName(s.VpcId)}`,
          href: `/vpc/subnet?id=${s.SubnetId}`,
          meta: (
            <>
              {s.DefaultForAz && <Pill tone="info">Default</Pill>}
              <Pill>{s.AvailabilityZone}</Pill>
              <span title="Available IPv4 addresses">{s.AvailableIpAddressCount} free</span>
            </>
          ),
          actions: <ActionForm action={deleteSubnet.bind(null, s.SubnetId!, undefined)} submit={`Delete ${s.SubnetId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.SubnetId}?`} />,
        })}
      />
    ),
  };
};

export const routesTab: Tab = async ({ vpcs, tables }) => {
  const vpcName = (id: string | undefined) => label(vpcs.find((x) => x.VpcId === id), id);
  return {
    actions: <CreateRouteTableSheet vpcs={vpcs} />,
    body: (
      <List
        label="Route tables"
        empty={<Empty icon={ICONS.routeTable} action={<CreateRouteTableSheet vpcs={vpcs} />} />}
        rows={tables.map((t) => {
          const main = t.Associations?.some((a) => a.Main);
          const explicit = t.Associations?.filter((a) => a.SubnetId).length ?? 0;
          const internet = t.Routes?.find((r) => r.DestinationCidrBlock === "0.0.0.0/0");
          const blackholes = t.Routes?.filter((r) => r.State === "blackhole").length ?? 0;
          return {
            key: t.RouteTableId!,
            icon: <AwsIcon icon={ICONS.routeTable} size={24} />,
            title: label(t, t.RouteTableId),
            subtitle: `${nameTag(t) ? `${t.RouteTableId} · ` : ""}${vpcName(t.VpcId)}`,
            href: `/vpc/rtb?id=${t.RouteTableId}`,
            meta: (
              <>
                {blackholes > 0 && <Status tone="bad">{`${blackholes} blackhole`}</Status>}
                {main && <Pill tone="info">Main</Pill>}
                {internet && <Pill title="0.0.0.0/0">→ {routeTarget(internet)}</Pill>}
                {explicit > 0 && <span>{explicit} subnets</span>}
              </>
            ),
            actions: main ? undefined : (
              <ActionForm action={deleteRouteTable.bind(null, t.RouteTableId!, undefined)} submit={`Delete ${t.RouteTableId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${t.RouteTableId}?`} />
            ),
          };
        })}
      />
    ),
  };
};

export const igwTab: Tab = async ({ vpcs }) => {
  const igws = await load(() => listIgws());
  if (!igws.ok) return { body: <ErrorNotice error={igws.error} /> };
  const attached = new Set(igws.value.flatMap((g) => (g.Attachments ?? []).map((a) => a.VpcId)));
  const free = vpcs.filter((v) => !attached.has(v.VpcId));
  const vpcName = (id: string | undefined) => label(vpcs.find((x) => x.VpcId === id), id);
  const create = (
    <Sheet title="Create internet gateway" label="Create internet gateway" testId="create-igw">
      <ActionForm action={createInternetGateway} submit="Create internet gateway" testId="create-igw">
        <Field label="Name" rule={NAME}>
          <input name="name" autoFocus />
        </Field>
        <VpcSelect vpcs={free} label="Attach to VPC" optional="Don't attach" defaultValue="" />
      </ActionForm>
    </Sheet>
  );
  return {
    actions: create,
    body: (
      <List
        label="Internet gateways"
        empty={<Empty icon={ICONS.igw} action={create} />}
        rows={igws.value.map((g) => {
          const id = g.InternetGatewayId!;
          const vpc = g.Attachments?.[0]?.VpcId;
          return {
            key: id,
            icon: <AwsIcon icon={ICONS.igw} size={24} />,
            title: label(g, id),
            subtitle: vpc ? vpcName(vpc) : nameTag(g) ? id : undefined,
            href: vpc ? `/vpc/${vpc}` : undefined,
            meta: <Status tone={vpc ? "good" : "neutral"}>{vpc ? "Attached" : "Detached"}</Status>,
            actions: (
              <>
                {vpc ? (
                  <ActionForm action={detachInternetGateway.bind(null, id, vpc)} submit={`Detach ${id}`} icon={<Unlink size={15} />} confirm={`Detach ${id} from ${vpcName(vpc)}?`} />
                ) : (
                  free.length > 0 && (
                    <Sheet title={`Attach ${id}`} label={`Attach ${id}`} icon={<Link2 size={15} />} testId={`attach-${id}`}>
                      <ActionForm action={attachInternetGateway.bind(null, id)} submit="Attach" testId={`attach-${id}`}>
                        <VpcSelect vpcs={free} />
                      </ActionForm>
                    </Sheet>
                  )
                )}
                <ActionForm action={deleteInternetGateway.bind(null, id, vpc)} submit={`Delete ${id}`} icon={<Trash2 size={15} />} tone="danger" confirm={vpc ? `Detach and delete ${id}?` : `Delete ${id}?`} />
              </>
            ),
          };
        })}
      />
    ),
  };
};

export const natTab: Tab = async ({ vpcs, subnets, tables }) => {
  const nats = await load(() => listNats());
  if (!nats.ok) return { body: <ErrorNotice error={nats.error} /> };
  const vpcName = (id: string | undefined) => label(vpcs.find((x) => x.VpcId === id), id);
  const subnetName = (id: string | undefined) => label(subnets.find((x) => x.SubnetId === id), id);
  const create = await natSheet(subnets, tables);
  return {
    actions: (
      <>
        <Link className="icon-button plain" href="/vpc?tab=eips" aria-label="Elastic IPs" title="Elastic IPs">
          <AwsIcon icon={ICONS.eip} size={18} />
        </Link>
        {create}
      </>
    ),
    body: (
      <List
        label="NAT gateways"
        empty={<Empty icon={ICONS.nat} action={create} />}
        rows={nats.value.map((n) => {
          const id = n.NatGatewayId!;
          const address = n.NatGatewayAddresses?.[0];
          return {
            key: id,
            icon: <AwsIcon icon={ICONS.nat} size={24} />,
            title: label(n, id),
            subtitle: [address?.PublicIp ?? address?.PrivateIp, subnetName(n.SubnetId), vpcName(n.VpcId)].filter(Boolean).join(" · "),
            href: `/vpc/${n.VpcId}`,
            meta: (
              <>
                {n.ConnectivityType === "private" && <Pill>Private</Pill>}
                {n.State === "failed" && n.FailureMessage && <span title={n.FailureMessage}>{n.FailureCode}</span>}
                <Status tone={STATE_TONE(n.State)}>{n.State}</Status>
              </>
            ),
            actions: n.State === "deleted" || n.State === "deleting" ? undefined : <DeleteNat id={id} hasEip={!!address?.AllocationId} />,
          };
        })}
      />
    ),
  };
};

export const eipsTab: Tab = async () => {
  const client = await ec2();
  const data = await load(async () => {
    const [addresses, nats, instances, enis] = await Promise.all([
      listAddresses(),
      listNats().catch(() => []),
      all((NextToken) => client.send(new DescribeInstancesCommand({ NextToken })), (r) => (r.Reservations ?? []).flatMap((x) => x.Instances ?? []), (r) => r.NextToken).catch(() => []),
      all((NextToken) => client.send(new DescribeNetworkInterfacesCommand({ NextToken })), (r) => r.NetworkInterfaces, (r) => r.NextToken).catch(() => []),
    ]);
    const ids = addresses.map((a) => a.AllocationId!).filter(Boolean);
    const dns = ids.length
      ? await all((NextToken) => client.send(new DescribeAddressesAttributeCommand({ AllocationIds: ids, Attribute: "domain-name", NextToken })), (r) => r.Addresses, (r) => r.NextToken).catch(() => [])
      : [];
    return { addresses, nats, instances, enis, dns };
  });
  const allocate = (
    <Sheet title="Allocate Elastic IP address" label="Allocate Elastic IP address" testId="allocate-eip">
      <ActionForm action={allocateAddress} submit="Allocate" testId="allocate-eip">
        <Field label="Name" rule={NAME}>
          <input name="name" autoFocus />
        </Field>
        <Field label="Network border group" rule={AllocateAddress.NetworkBorderGroup} member="NetworkBorderGroup" hint="The Region when empty">
          <input name="border" defaultValue={await region()} spellCheck={false} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!data.ok) return { actions: allocate, body: <ErrorNotice error={data.error} /> };
  const { addresses, nats, instances, enis, dns } = data.value;
  const live = instances.filter((i) => i.State?.Name === "running" || i.State?.Name === "stopped");
  const targets = [
    ...live.map((i) => ({ id: i.InstanceId!, label: `${label(i, i.InstanceId)} · ${i.PrivateIpAddress ?? ""}` })),
    ...enis.filter((e) => e.InterfaceType !== "natGateway").map((e) => ({ id: e.NetworkInterfaceId!, label: `${e.NetworkInterfaceId} · ${e.PrivateIpAddress ?? ""}${e.Description ? ` · ${e.Description}` : ""}` })),
  ];
  return {
    actions: allocate,
    body: (
      <List
        label="Elastic IPs"
        empty={<Empty icon={ICONS.eip} action={allocate} />}
        rows={addresses.map((a) => {
          const alloc = a.AllocationId!;
          const nat = nats.find((n) => n.State !== "deleted" && n.NatGatewayAddresses?.some((x) => x.AllocationId === alloc));
          const domain = dns.find((d) => d.AllocationId === alloc)?.PtrRecord;
          const to = a.InstanceId
            ? { text: label(instances.find((i) => i.InstanceId === a.InstanceId), a.InstanceId), href: `/ec2/instance?id=${a.InstanceId}` }
            : nat
              ? { text: label(nat, nat.NatGatewayId), href: `/vpc/${nat.VpcId}` }
              : a.NetworkInterfaceId
                ? { text: a.NetworkInterfaceId, href: undefined }
                : undefined;
          return {
            key: alloc,
            icon: <AwsIcon icon={ICONS.eip} size={24} />,
            title: <code>{a.PublicIp}</code>,
            subtitle: [nameTag(a), alloc, to && `→ ${to.text}${a.PrivateIpAddress ? ` (${a.PrivateIpAddress})` : ""}`].filter(Boolean).join(" · "),
            href: to?.href,
            meta: (
              <>
                {domain && <span title="Reverse DNS">{domain}</span>}
                {a.NetworkBorderGroup && <Pill>{a.NetworkBorderGroup}</Pill>}
                {!a.AssociationId && (
                  <Pill tone="warn" icon={<ShieldAlert size={11} />} title="Unassociated addresses are still charged">
                    Unassociated
                  </Pill>
                )}
              </>
            ),
            actions: (
              <>
                <Sheet title={`Reverse DNS for ${a.PublicIp}`} label={`Edit reverse DNS of ${a.PublicIp}`} icon={<Globe size={15} />}>
                  <ActionForm action={setReverseDns.bind(null, alloc)} submit="Save">
                    <Field label="Domain name" format="domain" member="DomainName" hint="Must resolve to this address; empty removes it">
                      <input name="domain" defaultValue={domain?.replace(/\.$/, "")} spellCheck={false} />
                    </Field>
                  </ActionForm>
                </Sheet>
                {a.AssociationId ? (
                  !nat && (
                    <ActionForm action={disassociateAddress.bind(null, a.AssociationId)} submit={`Disassociate ${a.PublicIp}`} icon={<Unlink size={15} />} confirm={`Disassociate ${a.PublicIp}?`} />
                  )
                ) : (
                  <Sheet title={`Associate ${a.PublicIp}`} label={`Associate ${a.PublicIp}`} icon={<Link2 size={15} />} testId={`associate-${alloc}`}>
                    <ActionForm action={associateAddress.bind(null, alloc)} submit="Associate" testId={`associate-${alloc}`}>
                      <Field label="Instance or network interface" member="InstanceId" known={targets.map((t) => t.id)}>
                        <select name="target" required>
                          {targets.map((t) => (
                            <option key={t.id} value={t.id}>
                              {t.label}
                            </option>
                          ))}
                        </select>
                      </Field>
                      <Field label="Private IP address" format="ipv4" member="PrivateIpAddress" hint="The primary address when empty">
                        <input name="privateIp" spellCheck={false} />
                      </Field>
                      <label className="check">
                        <input type="checkbox" name="reassociate" /> Allow this address to be reassociated
                      </label>
                    </ActionForm>
                  </Sheet>
                )}
                {!a.AssociationId && (
                  <ActionForm action={releaseAddress.bind(null, alloc)} submit={`Release ${a.PublicIp}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Release ${a.PublicIp}?`} />
                )}
              </>
            ),
          };
        })}
      />
    ),
  };
};

/** The VPCs with their route tables, subnets and security groups, for the
 * endpoint forms. */
export async function networkChoices({ vpcs, subnets, tables }: Net, groups?: Awaited<ReturnType<typeof listGroups>>): Promise<NetworkChoice[]> {
  const sgs = groups ?? (await listGroups().catch(() => []));
  return vpcs.map((v) => ({
    id: v.VpcId!,
    label: `${label(v, v.VpcId)} · ${v.CidrBlock}`,
    tables: tables.filter((t) => t.VpcId === v.VpcId).map((t) => ({ id: t.RouteTableId!, label: `${label(t, t.RouteTableId)}${t.Associations?.some((a) => a.Main) ? " · main" : ""}` })),
    subnets: subnets.filter((s) => s.VpcId === v.VpcId).map((s) => ({ id: s.SubnetId!, label: label(s, s.SubnetId), az: s.AvailabilityZone ?? "" })),
    groups: sgs.filter((g) => g.VpcId === v.VpcId).map((g) => ({ id: g.GroupId!, label: g.GroupName ?? g.GroupId! })),
  }));
}

export async function endpointServices() {
  const out = await (await ec2()).send(new DescribeVpcEndpointServicesCommand({})).catch(() => undefined);
  return (out?.ServiceDetails ?? []).map((s) => ({
    name: s.ServiceName!,
    types: (s.ServiceType ?? []).map((t) => t.ServiceType!).filter(Boolean),
    privateDns: !!s.PrivateDnsName,
  }));
}

export const endpointsTab: Tab = async (net) => {
  const vpcName = (id: string | undefined) => label(net.vpcs.find((x) => x.VpcId === id), id);
  const [eps, services, vpcs] = await Promise.all([load(() => listEndpoints()), endpointServices(), networkChoices(net)]);
  const create = (
    <Sheet title="Create endpoint" label="Create endpoint" testId="create-endpoint">
      <ActionForm action={createEndpoint} submit="Create endpoint" testId="create-endpoint">
        <EndpointFields services={services} vpcs={vpcs} />
      </ActionForm>
    </Sheet>
  );
  if (!eps.ok) return { actions: create, body: <ErrorNotice error={eps.error} /> };
  return {
    actions: create,
    body: (
      <Curated
        label="Endpoints"
        sections={[
          { id: "Interface", title: "Interface", items: eps.value.filter((e) => e.VpcEndpointType === "Interface") },
          { id: "Gateway", title: "Gateway", items: eps.value.filter((e) => e.VpcEndpointType !== "Interface") },
        ]}
        empty={<Empty icon={ICONS.endpoint} action={create} />}
        row={(e) => ({
          key: e.VpcEndpointId!,
          icon: <AwsIcon icon={knownService(e.ServiceName)?.icon ?? ICONS.endpoint} size={24} />,
          title: nameTag(e) ?? knownService(e.ServiceName)?.label ?? serviceKey(e.ServiceName),
          subtitle: `${nameTag(e) ? `${knownService(e.ServiceName)?.label ?? serviceKey(e.ServiceName)} · ` : ""}${vpcName(e.VpcId)}`,
          href: `/vpc/endpoint?id=${e.VpcEndpointId}`,
          meta: (
            <>
              <Pill>{e.VpcEndpointType}</Pill>
              <Status tone={STATE_TONE(e.State?.toLowerCase())}>{e.State?.toLowerCase() ?? ""}</Status>
            </>
          ),
          actions: <ActionForm action={deleteEndpoint.bind(null, e.VpcEndpointId!, undefined)} submit={`Delete ${e.VpcEndpointId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${e.VpcEndpointId}?`} />,
        })}
      />
    ),
  };
};

/** Peering actions by state and side: only the accepter accepts. */
export function PeeringActions({ id, code, accepter }: { id: string; code: string | undefined; accepter: boolean }) {
  return (
    <>
      {code === "pending-acceptance" && accepter && <ActionForm action={acceptPeering.bind(null, id)} submit={`Accept ${id}`} icon={<Check size={15} />} tone="primary" />}
      {code === "pending-acceptance" && accepter && <ActionForm action={rejectPeering.bind(null, id)} submit={`Reject ${id}`} icon={<Ban size={15} />} confirm={`Reject ${id}?`} />}
      {(code === "active" || code === "pending-acceptance" || code === "provisioning") && (
        <ActionForm action={deletePeering.bind(null, id)} submit={`Delete ${id}`} icon={<X size={15} />} tone="danger" confirm={`Delete ${id}?`} />
      )}
    </>
  );
}

export async function regions() {
  const out = await (await ec2()).send(new DescribeRegionsCommand({})).catch(() => undefined);
  return (out?.Regions ?? []).map((r) => r.RegionName!).sort();
}

export const peeringTab: Tab = async ({ vpcs }) => {
  const [pcx, names, here] = await Promise.all([load(() => listPeerings()), regions(), region()]);
  const mine = new Set(vpcs.map((v) => v.VpcId));
  const vpcName = (id: string | undefined) => (mine.has(id) ? label(vpcs.find((x) => x.VpcId === id), id) : id);
  const create = (
    <Sheet title="Create peering connection" label="Create peering connection" testId="create-peering">
      <ActionForm action={createPeering} submit="Create peering connection" testId="create-peering">
        <PeeringFields vpcs={vpcs.map((v) => ({ id: v.VpcId!, label: `${label(v, v.VpcId)} · ${v.CidrBlock}` }))} regions={names.length ? names : [here]} region={here} />
      </ActionForm>
    </Sheet>
  );
  if (!pcx.ok) return { actions: create, body: <ErrorNotice error={pcx.error} /> };
  return {
    actions: create,
    body: (
      <List
        label="Peering connections"
        empty={<Empty icon={ICONS.peering} action={create} />}
        rows={pcx.value.map((p) => {
          const id = p.VpcPeeringConnectionId!;
          const req = p.RequesterVpcInfo;
          const acc = p.AccepterVpcInfo;
          const accepter = mine.has(acc?.VpcId) && (acc?.Region ?? here) === here;
          const remote = [acc?.OwnerId !== req?.OwnerId && acc?.OwnerId, acc?.Region !== req?.Region && acc?.Region].filter(Boolean).join(" · ");
          return {
            key: id,
            icon: <AwsIcon icon={ICONS.peering} size={24} />,
            title: label(p, id),
            subtitle: `${vpcName(req?.VpcId)} (${req?.CidrBlock ?? "?"}) ⇄ ${vpcName(acc?.VpcId)}${acc?.CidrBlock ? ` (${acc.CidrBlock})` : ""}`,
            href: `/vpc/peering?id=${id}`,
            meta: (
              <>
                {remote && <Pill>{remote}</Pill>}
                {p.Status?.Code === "pending-acceptance" && <Pill tone="info">{accepter ? "Accepter" : "Requester"}</Pill>}
                <Status tone={STATE_TONE(p.Status?.Code)}>{p.Status?.Code ?? ""}</Status>
              </>
            ),
            actions: <PeeringActions id={id} code={p.Status?.Code} accepter={accepter} />,
          };
        })}
      />
    ),
  };
};

export function CreateAclSheet({ vpcs, vpc }: { vpcs: Vpc[]; vpc?: string }) {
  return (
    <Sheet title="Create network ACL" label="Create network ACL" icon={<Plus size={16} />} testId="create-acl">
      <ActionForm action={createAcl} submit="Create network ACL" testId="create-acl">
        <Field label="Name" rule={NAME}>
          <input name="name" autoFocus />
        </Field>
        {vpc ? <input type="hidden" name="vpc" value={vpc} /> : <VpcSelect vpcs={vpcs} />}
      </ActionForm>
    </Sheet>
  );
}

export const aclsTab: Tab = async ({ vpcs }) => {
  const acls = await load(() => listAcls());
  const vpcName = (id: string | undefined) => label(vpcs.find((x) => x.VpcId === id), id);
  const create = <CreateAclSheet vpcs={vpcs} />;
  if (!acls.ok) return { actions: create, body: <ErrorNotice error={acls.error} /> };
  return {
    actions: create,
    body: (
      <List
        label="Network ACLs"
        empty={<Empty icon={ICONS.nacl} action={create} />}
        rows={acls.value.map((a) => {
          const rules = a.Entries?.filter((e) => e.RuleNumber !== 32767) ?? [];
          const denies = rules.filter((e) => e.RuleAction === "deny").length;
          return {
            key: a.NetworkAclId!,
            icon: <AwsIcon icon={ICONS.nacl} size={24} />,
            title: label(a, a.NetworkAclId),
            subtitle: `${nameTag(a) ? `${a.NetworkAclId} · ` : ""}${vpcName(a.VpcId)}`,
            href: `/vpc/acl?id=${a.NetworkAclId}`,
            meta: (
              <>
                {denies > 0 && (
                  <Pill tone="warn" icon={<Ban size={11} />} title="Deny rules">
                    {denies}
                  </Pill>
                )}
                {a.IsDefault && <Pill tone="info">Default</Pill>}
                <span>{rules.length} rules</span>
                <span>{a.Associations?.length ?? 0} subnets</span>
              </>
            ),
          };
        })}
      />
    ),
  };
};
