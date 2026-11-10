"use server";

import {
  AcceptVpcPeeringConnectionCommand,
  AllocateAddressCommand,
  AssociateAddressCommand,
  CreateNetworkAclCommand,
  CreateNetworkAclEntryCommand,
  CreateVpcEndpointCommand,
  CreateVpcPeeringConnectionCommand,
  DeleteNetworkAclCommand,
  DeleteNetworkAclEntryCommand,
  DeleteVpcEndpointsCommand,
  DeleteVpcPeeringConnectionCommand,
  DescribeVpcEndpointsCommand,
  DisassociateAddressCommand,
  ModifyAddressAttributeCommand,
  ModifyVpcEndpointCommand,
  ModifyVpcPeeringConnectionOptionsCommand,
  RejectVpcPeeringConnectionCommand,
  ReleaseAddressCommand,
  ReplaceNetworkAclAssociationCommand,
  ReplaceNetworkAclEntryCommand,
  ResetAddressAttributeCommand,
  type VpcEndpointType,
} from "@aws-sdk/client-ec2";
import { act, checkFailures, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ec2, nameSpec } from "../../lib/clients";
import { PROTOCOLS } from "../../lib/acl";
import { listAcls } from "../../lib/vpc";

const PAGES = ["/vpc", "/vpc/[id]", "/vpc/subnet", "/vpc/rtb", "/vpc/endpoint", "/vpc/peering", "/vpc/acl"];

const values = (form: FormData, name: string) => form.getAll(name).map(String).filter(Boolean);
const diff = (now: string[], wanted: string[]) => ({ add: wanted.filter((x) => !now.includes(x)), remove: now.filter((x) => !wanted.includes(x)) });

// --- Elastic IPs --------------------------------------------------------------

export async function allocateAddress(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ec2()).send(
      new AllocateAddressCommand({
        Domain: "vpc",
        NetworkBorderGroup: text(form, "border") || undefined,
        TagSpecifications: nameSpec("elastic-ip", text(form, "name")),
      }),
    );
    return `Allocated ${out.PublicIp}`;
  }, { revalidate: PAGES, fields: { NetworkBorderGroup: "border" } });
}

export async function releaseAddress(allocationId: string) {
  return act(async () => {
    await (await ec2()).send(new ReleaseAddressCommand({ AllocationId: allocationId }));
    return "Released";
  }, ...PAGES);
}

export async function associateAddress(allocationId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const target = required(form, "target", "Instance or network interface");
    const out = await (await ec2()).send(
      new AssociateAddressCommand({
        AllocationId: allocationId,
        ...(target.startsWith("eni-") ? { NetworkInterfaceId: target } : { InstanceId: target }),
        PrivateIpAddress: text(form, "privateIp") || undefined,
        AllowReassociation: form.get("reassociate") === "on",
      }),
    );
    return `Associated (${out.AssociationId})`;
  }, {
    revalidate: PAGES,
    fields: {
      InstanceId: "target",
      NetworkInterfaceId: "target",
      PrivateIpAddress: "privateIp",
      "InvalidInstanceID.NotFound": "target",
      "InvalidNetworkInterfaceID.NotFound": "target",
      "Resource.AlreadyAssociated": "reassociate",
      "Gateway.NotAttached": "target",
    },
  });
}

export async function disassociateAddress(associationId: string) {
  return act(async () => {
    await (await ec2()).send(new DisassociateAddressCommand({ AssociationId: associationId }));
    return "Disassociated";
  }, ...PAGES);
}

/** Reverse DNS: a domain that resolves to the address, or none. */
export async function setReverseDns(allocationId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const DomainName = text(form, "domain");
    if (DomainName) await client.send(new ModifyAddressAttributeCommand({ AllocationId: allocationId, DomainName }));
    else await client.send(new ResetAddressAttributeCommand({ AllocationId: allocationId, Attribute: "domain-name" }));
    return DomainName ? `Reverse DNS ${DomainName}` : "Reverse DNS removed";
  }, { revalidate: PAGES, fields: { DomainName: "domain" } });
}

// --- Endpoints ----------------------------------------------------------------

export async function createEndpoint(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const VpcId = required(form, "vpc", "VPC");
    const ServiceName = required(form, "service", "Service");
    const type = (text(form, "type") || "Gateway") as VpcEndpointType;
    const PolicyDocument = text(form, "policy") || undefined;
    const gateway = type === "Gateway";
    const SubnetIds = values(form, "subnet");
    if (!gateway && SubnetIds.length === 0) throw new FieldError("subnet", "Pick at least one subnet", "required");
    const ep = (
      await (await ec2()).send(
        new CreateVpcEndpointCommand({
          VpcId,
          ServiceName,
          VpcEndpointType: type,
          PolicyDocument,
          RouteTableIds: gateway ? values(form, "table") : undefined,
          SubnetIds: gateway ? undefined : SubnetIds,
          SecurityGroupIds: gateway ? undefined : values(form, "group"),
          PrivateDnsEnabled: gateway ? undefined : form.get("privateDns") === "on",
          TagSpecifications: nameSpec("vpc-endpoint", text(form, "name")),
        }),
      )
    ).VpcEndpoint!;
    redirect(`/vpc/endpoint?id=${ep.VpcEndpointId}`);
  }, {
    fields: {
      ServiceName: "service",
      PolicyDocument: "policy",
      "InvalidServiceName": "service",
      "InvalidVpcID.NotFound": "vpc",
      "InvalidRouteTableId.NotFound": "table",
      "InvalidSubnetID.NotFound": "subnet",
      DuplicateSubnetsInSameZone: "subnet",
      "MalformedPolicyDocument": "policy",
    },
  });
}

/** Save an endpoint's route tables, subnets, security groups and private DNS
 * as checked (only what the endpoint's type has). */
export async function editEndpointNetwork(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const ep = (await client.send(new DescribeVpcEndpointsCommand({ VpcEndpointIds: [id] }))).VpcEndpoints?.[0];
    if (!ep) throw new Error(`${id} not found`);
    if (ep.VpcEndpointType === "Gateway") {
      const t = diff(ep.RouteTableIds ?? [], values(form, "table"));
      await client.send(new ModifyVpcEndpointCommand({ VpcEndpointId: id, AddRouteTableIds: t.add, RemoveRouteTableIds: t.remove }));
    } else {
      const s = diff(ep.SubnetIds ?? [], values(form, "subnet"));
      const g = diff((ep.Groups ?? []).map((x) => x.GroupId!), values(form, "group"));
      if (!values(form, "subnet").length) throw new FieldError("subnet", "Keep at least one subnet", "required");
      await client.send(
        new ModifyVpcEndpointCommand({
          VpcEndpointId: id,
          AddSubnetIds: s.add,
          RemoveSubnetIds: s.remove,
          AddSecurityGroupIds: g.add,
          RemoveSecurityGroupIds: g.remove,
          PrivateDnsEnabled: form.get("privateDns") === "on",
        }),
      );
    }
    return "Endpoint updated";
  }, { revalidate: PAGES, fields: { DuplicateSubnetsInSameZone: "subnet" } });
}

export async function editEndpointPolicy(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = text(form, "policy");
    await (await ec2()).send(new ModifyVpcEndpointCommand({ VpcEndpointId: id, ...(policy ? { PolicyDocument: policy } : { ResetPolicy: true }) }));
    return policy ? "Policy saved" : "Policy reset to full access";
  }, { revalidate: PAGES, fields: { PolicyDocument: "policy", MalformedPolicyDocument: "policy" } });
}

export async function deleteEndpoint(id: string, back?: string) {
  return act(async () => {
    const out = await (await ec2()).send(new DeleteVpcEndpointsCommand({ VpcEndpointIds: [id] }));
    checkFailures(out.Unsuccessful, (u) => `${u.ResourceId}: ${u.Error?.Message ?? u.Error?.Code}`);
    if (back) redirect(back);
    return "Endpoint deleted";
  }, ...PAGES);
}

// --- Peering ------------------------------------------------------------------

export async function createPeering(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const VpcId = required(form, "vpc", "Requester VPC");
    const PeerVpcId = required(form, "peer", "Accepter VPC");
    if (PeerVpcId === VpcId) throw new FieldError("peer", "Pick another VPC");
    const pcx = (
      await (await ec2()).send(
        new CreateVpcPeeringConnectionCommand({
          VpcId,
          PeerVpcId,
          PeerOwnerId: text(form, "account") || undefined,
          PeerRegion: text(form, "region") || undefined,
          TagSpecifications: nameSpec("vpc-peering-connection", text(form, "name")),
        }),
      )
    ).VpcPeeringConnection!;
    redirect(`/vpc/peering?id=${pcx.VpcPeeringConnectionId}`);
  }, {
    fields: { VpcId: "vpc", PeerVpcId: "peer", PeerOwnerId: "account", PeerRegion: "region", "InvalidVpcID.NotFound": "peer", InvalidRegion: "region" },
  });
}

export async function acceptPeering(id: string) {
  return act(async () => {
    await (await ec2()).send(new AcceptVpcPeeringConnectionCommand({ VpcPeeringConnectionId: id }));
    return "Accepted";
  }, ...PAGES);
}

export async function rejectPeering(id: string) {
  return act(async () => {
    await (await ec2()).send(new RejectVpcPeeringConnectionCommand({ VpcPeeringConnectionId: id }));
    return "Rejected";
  }, ...PAGES);
}

export async function deletePeering(id: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteVpcPeeringConnectionCommand({ VpcPeeringConnectionId: id }));
    return "Deleted";
  }, ...PAGES);
}

/** DNS resolution across the peering, for the side this account owns. */
export async function editPeeringDns(id: string, side: "requester" | "accepter", _: ActionResult | null, form: FormData) {
  return act(async () => {
    const options = { AllowDnsResolutionFromRemoteVpc: form.get("dns") === "on" };
    await (await ec2()).send(
      new ModifyVpcPeeringConnectionOptionsCommand({
        VpcPeeringConnectionId: id,
        ...(side === "requester" ? { RequesterPeeringConnectionOptions: options } : { AccepterPeeringConnectionOptions: options }),
      }),
    );
    return "DNS settings saved";
  }, ...PAGES);
}

// --- Network ACLs -------------------------------------------------------------

export async function createAcl(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const VpcId = required(form, "vpc", "VPC");
    const acl = (await (await ec2()).send(new CreateNetworkAclCommand({ VpcId, TagSpecifications: nameSpec("network-acl", text(form, "name")) }))).NetworkAcl!;
    redirect(`/vpc/acl?id=${acl.NetworkAclId}`);
  }, { fields: { VpcId: "vpc", "InvalidVpcID.NotFound": "vpc" } });
}

export async function deleteAcl(id: string, back?: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteNetworkAclCommand({ NetworkAclId: id }));
    if (back) redirect(back);
    return "Network ACL deleted";
  }, ...PAGES);
}

interface Entry {
  Protocol: string;
  RuleAction: "allow" | "deny";
  CidrBlock?: string;
  Ipv6CidrBlock?: string;
  PortRange?: { From: number; To: number };
  IcmpTypeCode?: { Type: number; Code: number };
}

function entryFrom(form: FormData): Entry {
  const protocol = text(form, "protocol") || "-1";
  const known = PROTOCOLS.find((p) => p.value === protocol);
  const Protocol = protocol === "custom" ? required(form, "protocolNumber", "Protocol number") : protocol;
  const source = required(form, "cidr", "CIDR");
  const ports = text(form, "ports");
  let PortRange: Entry["PortRange"];
  if (known?.ports || (protocol === "custom" && ports)) {
    if (!ports) throw new FieldError("ports", "Port range is required", "required");
    const [from, to = from] = ports.split("-").map((p) => Number(p.trim()));
    PortRange = { From: from, To: to };
  }
  return {
    Protocol,
    RuleAction: text(form, "action") === "deny" ? ("deny" as const) : ("allow" as const),
    ...(source.includes(":") ? { Ipv6CidrBlock: source } : { CidrBlock: source }),
    PortRange,
    IcmpTypeCode: Protocol === "1" || Protocol === "58" ? { Type: -1, Code: -1 } : undefined,
  };
}

const ENTRY_FIELDS = { RuleNumber: "number", CidrBlock: "cidr", Ipv6CidrBlock: "cidr", PortRange: "ports", Protocol: "protocol", NetworkAclEntryAlreadyExists: "number" };

export async function addAclEntry(acl: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const RuleNumber = Number(required(form, "number", "Rule number"));
    const Egress = text(form, "direction") === "outbound";
    await (await ec2()).send(new CreateNetworkAclEntryCommand({ NetworkAclId: acl, RuleNumber, Egress, ...entryFrom(form) }));
    return `Rule ${RuleNumber} added`;
  }, { revalidate: PAGES, fields: ENTRY_FIELDS });
}

export async function replaceAclEntry(acl: string, egress: boolean, number: number, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ec2()).send(new ReplaceNetworkAclEntryCommand({ NetworkAclId: acl, RuleNumber: number, Egress: egress, ...entryFrom(form) }));
    return `Rule ${number} updated`;
  }, { revalidate: PAGES, fields: ENTRY_FIELDS });
}

export async function deleteAclEntry(acl: string, egress: boolean, number: number) {
  return act(async () => {
    await (await ec2()).send(new DeleteNetworkAclEntryCommand({ NetworkAclId: acl, RuleNumber: number, Egress: egress }));
    return `Rule ${number} deleted`;
  }, ...PAGES);
}

/** Put one subnet on a network ACL. */
export async function moveSubnetAcl(subnet: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const acl = required(form, "acl", "Network ACL");
    const assoc = (await listAcls()).flatMap((a) => (a.Associations ?? []).map((x) => ({ ...x, acl: a.NetworkAclId }))).find((x) => x.SubnetId === subnet);
    if (!assoc) throw new Error(`${subnet} has no network ACL association`);
    if (assoc.acl === acl) return "No change";
    await (await ec2()).send(new ReplaceNetworkAclAssociationCommand({ AssociationId: assoc.NetworkAclAssociationId!, NetworkAclId: acl }));
    return `Associated with ${acl}`;
  }, ...PAGES);
}

/** "Edit subnet associations": move the checked subnets onto this ACL. A
 * subnet always has one ACL, so taking one off means moving it back to the
 * VPC's default. */
export async function editAclSubnets(acl: string, vpc: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const wanted = new Set(values(form, "subnet"));
    const acls = await listAcls(vpc);
    const fallback = acls.find((a) => a.IsDefault)?.NetworkAclId;
    let changed = 0;
    for (const a of acls) {
      for (const assoc of a.Associations ?? []) {
        const here = a.NetworkAclId === acl;
        const want = wanted.has(assoc.SubnetId!);
        if (here === want) continue;
        const to = want ? acl : fallback;
        if (!to || to === a.NetworkAclId) continue;
        await client.send(new ReplaceNetworkAclAssociationCommand({ AssociationId: assoc.NetworkAclAssociationId!, NetworkAclId: to }));
        changed++;
      }
    }
    return changed ? `${changed} subnet${changed === 1 ? "" : "s"} moved` : "No change";
  }, ...PAGES);
}
