"use server";

import {
  AllocateAddressCommand,
  AssociateRouteTableCommand,
  AssociateVpcCidrBlockCommand,
  AttachInternetGatewayCommand,
  CreateDefaultVpcCommand,
  CreateInternetGatewayCommand,
  CreateNatGatewayCommand,
  CreateRouteCommand,
  CreateRouteTableCommand,
  CreateSubnetCommand,
  CreateVpcCommand,
  DeleteEgressOnlyInternetGatewayCommand,
  DeleteInternetGatewayCommand,
  DeleteNatGatewayCommand,
  DeleteNetworkAclCommand,
  DeleteRouteCommand,
  DeleteRouteTableCommand,
  DeleteSecurityGroupCommand,
  DeleteSubnetCommand,
  DeleteVpcCommand,
  DeleteVpcEndpointsCommand,
  DeleteVpcPeeringConnectionCommand,
  DescribeAvailabilityZonesCommand,
  DescribeEgressOnlyInternetGatewaysCommand,
  DescribeNatGatewaysCommand,
  DetachInternetGatewayCommand,
  DisableVgwRoutePropagationCommand,
  DisassociateRouteTableCommand,
  DisassociateVpcCidrBlockCommand,
  EnableVgwRoutePropagationCommand,
  ModifySubnetAttributeCommand,
  ModifyVpcAttributeCommand,
  ReleaseAddressCommand,
  ReplaceRouteCommand,
  ReplaceRouteTableAssociationCommand,
  RevokeSecurityGroupEgressCommand,
  RevokeSecurityGroupIngressCommand,
} from "@aws-sdk/client-ec2";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { wantsAuto } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { ec2, nameSpec } from "../../lib/clients";
import { destinationOf, targetKey } from "../../lib/routes";
import { listAcls, listEndpoints, listGroups, listIgws, listNats, listPeerings, listSubnets, listTables } from "../../lib/vpc";

/** Every VPC page: a change to one resource shows on the others. */
const PAGES = ["/vpc", "/vpc/[id]", "/vpc/subnet", "/vpc/rtb", "/vpc/endpoint", "/vpc/peering", "/vpc/acl"];

/** EC2's CIDR rejections, as problems with the CIDR field (they would
 * otherwise read as name conflicts, or show under the form). */
async function cidr<T>(send: () => Promise<T>): Promise<T> {
  try {
    return await send();
  } catch (e) {
    const name = e instanceof Error ? e.name : "";
    if (name === "InvalidSubnet.Conflict") throw new FieldError("cidr", "Overlaps another subnet");
    if (name === "InvalidSubnet.Range") throw new FieldError("cidr", "Outside the VPC, or not /16 to /28");
    if (name === "InvalidVpc.Range") throw new FieldError("cidr", "Netmask /16 to /28");
    if (name === "CidrConflict" || name === "InvalidVpc.CidrConflict") throw new FieldError("cidr", e instanceof Error ? e.message : "Overlaps");
    if (name === "InvalidParameterValue" && e instanceof Error && /cidrBlock/i.test(e.message)) throw new FieldError("cidr", "Not a network address");
    throw e;
  }
}

/** Split a /16 into /20s: the n-th block. */
function split(cidr: string, n: number) {
  const [ip, bits] = cidr.split("/");
  const octets = ip.split(".").map(Number);
  const value = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const size = Math.min(Math.max(Number(bits) + 4, 20), 28);
  const next = (value + n * 2 ** (32 - size)) >>> 0;
  return `${[next >>> 24, (next >>> 16) & 255, (next >>> 8) & 255, next & 255].join(".")}/${size}`;
}

// --- VPCs -------------------------------------------------------------------

export async function createVpc(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = text(form, "name");
    const block = required(form, "cidr", "IPv4 CIDR");
    const client = await ec2();
    const layout = text(form, "layout");
    // Four subnets of at least /28 need a /26 or larger.
    if (layout === "public-private" && Number(block.split("/")[1]) > 26) throw new FieldError("cidr", "Netmask /16 to /26 for four subnets");
    const vpc = (await cidr(() => client.send(new CreateVpcCommand({ CidrBlock: block, TagSpecifications: nameSpec("vpc", name) })))).Vpc!;
    const VpcId = vpc.VpcId!;
    await client.send(new ModifyVpcAttributeCommand({ VpcId, EnableDnsHostnames: { Value: true } }));
    if (layout === "public-private") {
      // "VPC and more": a public and a private subnet in each of two zones,
      // an internet gateway, and a public route table.
      const zones = ((await client.send(new DescribeAvailabilityZonesCommand({}))).AvailabilityZones ?? []).slice(0, 2).map((z) => z.ZoneName!);
      const igw = (await client.send(new CreateInternetGatewayCommand({ TagSpecifications: nameSpec("internet-gateway", name && `${name}-igw`) }))).InternetGateway!;
      await client.send(new AttachInternetGatewayCommand({ VpcId, InternetGatewayId: igw.InternetGatewayId! }));
      const rt = (await client.send(new CreateRouteTableCommand({ VpcId, TagSpecifications: nameSpec("route-table", name && `${name}-rtb-public`) }))).RouteTable!;
      await client.send(new CreateRouteCommand({ RouteTableId: rt.RouteTableId!, DestinationCidrBlock: "0.0.0.0/0", GatewayId: igw.InternetGatewayId! }));
      let n = 0;
      for (const kind of ["public", "private"]) {
        for (const az of zones) {
          const subnet = (
            await client.send(
              new CreateSubnetCommand({ VpcId, AvailabilityZone: az, CidrBlock: split(block, n++), TagSpecifications: nameSpec("subnet", `${name || VpcId}-subnet-${kind}-${az}`) }),
            )
          ).Subnet!;
          if (kind === "public") {
            await client.send(new AssociateRouteTableCommand({ RouteTableId: rt.RouteTableId!, SubnetId: subnet.SubnetId! }));
            await client.send(new ModifySubnetAttributeCommand({ SubnetId: subnet.SubnetId!, MapPublicIpOnLaunch: { Value: true } }));
          }
        }
      }
    }
    redirect(`/vpc/${VpcId}`);
  }, { fields: { CidrBlock: "cidr" } });
}

/** Delete a VPC the way the VPC console does: its endpoints, peering
 * connections, subnets, custom route tables, security groups, network ACLs
 * and gateways first. NAT gateways have to go first, as in AWS. */
export async function deleteVpc(id: string) {
  return act(async () => {
    const client = await ec2();
    const [nats, endpoints, peerings, subnets, tables, groups, acls, igws, eigws] = await Promise.all([
      listNats(id),
      listEndpoints(id),
      listPeerings(),
      listSubnets(id),
      listTables(id),
      listGroups(id),
      listAcls(id),
      listIgws(id),
      client.send(new DescribeEgressOnlyInternetGatewaysCommand({})).then((r) => (r.EgressOnlyInternetGateways ?? []).filter((g) => g.Attachments?.some((a) => a.VpcId === id))),
    ]);
    const live = nats.filter((n) => n.State !== "deleted" && n.State !== "deleting");
    if (live.length) throw new Error(`Delete the NAT gateways first: ${live.map((n) => n.NatGatewayId).join(", ")}`);
    const endpointIds = endpoints.filter((e) => e.State?.toLowerCase() !== "deleted").map((e) => e.VpcEndpointId!);
    if (endpointIds.length) await client.send(new DeleteVpcEndpointsCommand({ VpcEndpointIds: endpointIds }));
    for (const p of peerings) {
      const mine = p.RequesterVpcInfo?.VpcId === id || p.AccepterVpcInfo?.VpcId === id;
      if (mine && ["active", "pending-acceptance", "provisioning"].includes(p.Status?.Code ?? "")) {
        await client.send(new DeleteVpcPeeringConnectionCommand({ VpcPeeringConnectionId: p.VpcPeeringConnectionId! }));
      }
    }
    for (const s of subnets) await client.send(new DeleteSubnetCommand({ SubnetId: s.SubnetId! }));
    for (const t of tables) if (!t.Associations?.some((a) => a.Main)) await client.send(new DeleteRouteTableCommand({ RouteTableId: t.RouteTableId! }));
    // Rules that name other groups would keep them alive: revoke them all first.
    for (const g of groups) {
      if (g.IpPermissions?.length) await client.send(new RevokeSecurityGroupIngressCommand({ GroupId: g.GroupId!, IpPermissions: g.IpPermissions }));
      if (g.GroupName !== "default" && g.IpPermissionsEgress?.length) await client.send(new RevokeSecurityGroupEgressCommand({ GroupId: g.GroupId!, IpPermissions: g.IpPermissionsEgress }));
    }
    for (const g of groups) if (g.GroupName !== "default") await client.send(new DeleteSecurityGroupCommand({ GroupId: g.GroupId! }));
    for (const a of acls) if (!a.IsDefault) await client.send(new DeleteNetworkAclCommand({ NetworkAclId: a.NetworkAclId! }));
    for (const g of igws) {
      await client.send(new DetachInternetGatewayCommand({ InternetGatewayId: g.InternetGatewayId!, VpcId: id }));
      await client.send(new DeleteInternetGatewayCommand({ InternetGatewayId: g.InternetGatewayId! }));
    }
    for (const g of eigws) await client.send(new DeleteEgressOnlyInternetGatewayCommand({ EgressOnlyInternetGatewayId: g.EgressOnlyInternetGatewayId! }));
    await client.send(new DeleteVpcCommand({ VpcId: id }));
    redirect("/vpc");
  });
}

export async function createDefaultVpc() {
  return act(async () => {
    const vpc = (await (await ec2()).send(new CreateDefaultVpcCommand({}))).Vpc;
    return `Default VPC ${vpc?.VpcId} created`;
  }, ...PAGES);
}

export async function editVpcDns(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    // One attribute per call, as EC2 requires; hostnames need DNS support.
    const support = form.get("support") === "on";
    const hostnames = form.get("hostnames") === "on";
    if (hostnames && !support) throw new Error("DNS hostnames need DNS resolution");
    if (support) await client.send(new ModifyVpcAttributeCommand({ VpcId: id, EnableDnsSupport: { Value: true } }));
    await client.send(new ModifyVpcAttributeCommand({ VpcId: id, EnableDnsHostnames: { Value: hostnames } }));
    if (!support) await client.send(new ModifyVpcAttributeCommand({ VpcId: id, EnableDnsSupport: { Value: false } }));
    return "DNS settings saved";
  }, ...PAGES);
}

export async function addVpcCidr(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    if (form.get("ipv6") === "on") {
      await client.send(new AssociateVpcCidrBlockCommand({ VpcId: id, AmazonProvidedIpv6CidrBlock: true }));
      return "IPv6 CIDR associated";
    }
    const CidrBlock = required(form, "cidr", "IPv4 CIDR");
    await cidr(() => client.send(new AssociateVpcCidrBlockCommand({ VpcId: id, CidrBlock })));
    return `${CidrBlock} associated`;
  }, { revalidate: PAGES, fields: { CidrBlock: "cidr" } });
}

export async function removeVpcCidr(associationId: string) {
  return act(async () => {
    await (await ec2()).send(new DisassociateVpcCidrBlockCommand({ AssociationId: associationId }));
    return "CIDR disassociated";
  }, ...PAGES);
}

// --- Subnets ------------------------------------------------------------------

export async function createSubnet(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const VpcId = required(form, "vpc", "VPC");
    const client = await ec2();
    await cidr(() =>
      client.send(
        new CreateSubnetCommand({
          VpcId,
          CidrBlock: required(form, "cidr", "IPv4 CIDR"),
          AvailabilityZone: text(form, "az") || undefined,
          TagSpecifications: nameSpec("subnet", text(form, "name")),
        }),
      ),
    );
    return "Subnet created";
  }, { revalidate: PAGES, fields: { CidrBlock: "cidr", AvailabilityZone: "az", "InvalidVpcID.NotFound": "vpc" } });
}

export async function deleteSubnet(id: string, back?: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteSubnetCommand({ SubnetId: id }));
    if (back) redirect(back);
    return "Subnet deleted";
  }, ...PAGES);
}

export async function editSubnet(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ec2()).send(new ModifySubnetAttributeCommand({ SubnetId: id, MapPublicIpOnLaunch: { Value: form.get("publicIp") === "on" } }));
    return "Subnet settings saved";
  }, ...PAGES);
}

// --- Internet gateways --------------------------------------------------------

export async function createInternetGateway(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const igw = (await client.send(new CreateInternetGatewayCommand({ TagSpecifications: nameSpec("internet-gateway", text(form, "name")) }))).InternetGateway!;
    const vpc = text(form, "vpc");
    if (vpc) await client.send(new AttachInternetGatewayCommand({ VpcId: vpc, InternetGatewayId: igw.InternetGatewayId! }));
    return vpc ? `Attached ${igw.InternetGatewayId}` : `Created ${igw.InternetGatewayId}`;
  }, { revalidate: PAGES, fields: { "Resource.AlreadyAssociated": "vpc", "InvalidVpcID.NotFound": "vpc" } });
}

export async function attachNewInternetGateway(vpc: string) {
  return act(async () => {
    const client = await ec2();
    const igw = (await client.send(new CreateInternetGatewayCommand({}))).InternetGateway!;
    await client.send(new AttachInternetGatewayCommand({ VpcId: vpc, InternetGatewayId: igw.InternetGatewayId! }));
    return `Attached ${igw.InternetGatewayId}`;
  }, ...PAGES);
}

export async function attachInternetGateway(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const VpcId = required(form, "vpc", "VPC");
    await (await ec2()).send(new AttachInternetGatewayCommand({ VpcId, InternetGatewayId: id }));
    return `Attached to ${VpcId}`;
  }, { revalidate: PAGES, fields: { "Resource.AlreadyAssociated": "vpc", "InvalidVpcID.NotFound": "vpc" } });
}

export async function detachInternetGateway(id: string, vpc: string) {
  return act(async () => {
    await (await ec2()).send(new DetachInternetGatewayCommand({ InternetGatewayId: id, VpcId: vpc }));
    return "Detached";
  }, ...PAGES);
}

export async function deleteInternetGateway(id: string, vpc: string | undefined) {
  return act(async () => {
    const client = await ec2();
    if (vpc) await client.send(new DetachInternetGatewayCommand({ InternetGatewayId: id, VpcId: vpc }));
    await client.send(new DeleteInternetGatewayCommand({ InternetGatewayId: id }));
    return "Internet gateway deleted";
  }, ...PAGES);
}

// --- NAT gateways -------------------------------------------------------------

export async function createNatGateway(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const SubnetId = required(form, "subnet", "Subnet");
    const priv = text(form, "connectivity") === "private";
    let AllocationId: string | undefined;
    let allocated = false;
    if (!priv) {
      if (wantsAuto(form, "eip") || !text(form, "eip")) {
        AllocationId = (await client.send(new AllocateAddressCommand({ Domain: "vpc" }))).AllocationId;
        allocated = true;
      } else AllocationId = text(form, "eip");
    }
    try {
      const nat = (
        await client.send(
          new CreateNatGatewayCommand({
            SubnetId,
            AllocationId,
            ConnectivityType: priv ? "private" : "public",
            TagSpecifications: nameSpec("natgateway", text(form, "name")),
          }),
        )
      ).NatGateway!;
      return `Created ${nat.NatGatewayId}`;
    } catch (e) {
      // Don't leak the address this form just allocated.
      if (allocated && AllocationId) await client.send(new ReleaseAddressCommand({ AllocationId })).catch(() => {});
      throw e;
    }
  }, { revalidate: PAGES, fields: { SubnetId: "subnet", AllocationId: "eip", "InvalidSubnetID.NotFound": "subnet", "InvalidAllocationID.NotFound": "eip", "Resource.AlreadyAssociated": "eip" } });
}

export async function deleteNatGateway(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const nat = (await client.send(new DescribeNatGatewaysCommand({ NatGatewayIds: [id] }))).NatGateways?.[0];
    await client.send(new DeleteNatGatewayCommand({ NatGatewayId: id }));
    if (form.get("release") !== "on") return "NAT gateway deleting";
    // The address is free once the NAT has let it go.
    const allocations = (nat?.NatGatewayAddresses ?? []).map((a) => a.AllocationId).filter((a): a is string => !!a);
    for (const AllocationId of allocations) {
      for (let attempt = 0; ; attempt++) {
        try {
          await client.send(new ReleaseAddressCommand({ AllocationId }));
          break;
        } catch (e) {
          if (attempt >= 10 || !(e instanceof Error) || e.name !== "InvalidIPAddress.InUse") throw e;
          await new Promise((r) => setTimeout(r, 1000));
        }
      }
    }
    return allocations.length ? `NAT gateway deleted, ${allocations.length === 1 ? "Elastic IP" : `${allocations.length} Elastic IPs`} released` : "NAT gateway deleting";
  }, ...PAGES);
}

// --- Route tables -------------------------------------------------------------

export async function createRouteTable(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const VpcId = required(form, "vpc", "VPC");
    const t = (await (await ec2()).send(new CreateRouteTableCommand({ VpcId, TagSpecifications: nameSpec("route-table", text(form, "name")) }))).RouteTable!;
    return `Created ${t.RouteTableId}`;
  }, { revalidate: PAGES, fields: { VpcId: "vpc", "InvalidVpcID.NotFound": "vpc" } });
}

export async function deleteRouteTable(id: string, back?: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteRouteTableCommand({ RouteTableId: id }));
    if (back) redirect(back);
    return "Route table deleted";
  }, ...PAGES);
}

/** "Edit subnet associations": the checked subnets end up on this table,
 * moved off whichever table they were on; unchecked ones go back to main. */
export async function editTableSubnets(table: string, vpc: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const wanted = new Set(form.getAll("subnet").map(String));
    const tables = await listTables(vpc);
    const explicit = tables.flatMap((t) => (t.Associations ?? []).filter((a) => a.SubnetId && !a.Main).map((a) => ({ table: t.RouteTableId!, subnet: a.SubnetId!, id: a.RouteTableAssociationId! })));
    let changed = 0;
    for (const a of explicit) {
      if (a.table === table && !wanted.has(a.subnet)) {
        await client.send(new DisassociateRouteTableCommand({ AssociationId: a.id }));
        changed++;
      }
    }
    for (const subnet of wanted) {
      const current = explicit.find((a) => a.subnet === subnet);
      if (current?.table === table) continue;
      if (current) await client.send(new ReplaceRouteTableAssociationCommand({ AssociationId: current.id, RouteTableId: table }));
      else await client.send(new AssociateRouteTableCommand({ RouteTableId: table, SubnetId: subnet }));
      changed++;
    }
    return changed ? `${changed} association${changed === 1 ? "" : "s"} changed` : "No change";
  }, ...PAGES);
}

/** Put one subnet on a table, moving it off its current one. */
export async function moveSubnetTable(subnet: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ec2();
    const table = required(form, "table", "Route table");
    const [s] = await listSubnets(undefined, [subnet]);
    const current = (await listTables(s?.VpcId)).flatMap((t) => (t.Associations ?? []).map((a) => ({ ...a, table: t.RouteTableId }))).find((a) => a.SubnetId === subnet);
    if (current?.table === table) return "No change";
    if (current) await client.send(new ReplaceRouteTableAssociationCommand({ AssociationId: current.RouteTableAssociationId!, RouteTableId: table }));
    else await client.send(new AssociateRouteTableCommand({ RouteTableId: table, SubnetId: subnet }));
    return `Associated with ${table}`;
  }, ...PAGES);
}

export async function disassociateTable(associationId: string) {
  return act(async () => {
    await (await ec2()).send(new DisassociateRouteTableCommand({ AssociationId: associationId }));
    return "Disassociated";
  }, ...PAGES);
}

/** Make a table the VPC's main one (its implicit subnets follow). */
export async function setMainTable(table: string, vpc: string) {
  return act(async () => {
    const main = (await listTables(vpc)).flatMap((t) => t.Associations ?? []).find((a) => a.Main);
    if (!main?.RouteTableAssociationId) throw new Error(`${vpc} has no main route table association`);
    await (await ec2()).send(new ReplaceRouteTableAssociationCommand({ AssociationId: main.RouteTableAssociationId, RouteTableId: table }));
    return "Main route table set";
  }, ...PAGES);
}

export async function setPropagation(table: string, gateway: string, enable: boolean) {
  return act(async () => {
    const client = await ec2();
    if (enable) await client.send(new EnableVgwRoutePropagationCommand({ RouteTableId: table, GatewayId: gateway }));
    else await client.send(new DisableVgwRoutePropagationCommand({ RouteTableId: table, GatewayId: gateway }));
    return enable ? "Propagation enabled" : "Propagation disabled";
  }, ...PAGES);
}

const ROUTE_FIELDS = {
  DestinationCidrBlock: "destination",
  DestinationIpv6CidrBlock: "destination",
  DestinationPrefixListId: "destination",
  RouteAlreadyExists: "destination",
  "InvalidPrefixListID.NotFound": "destination",
  "InvalidGatewayID.NotFound": "target",
  "InvalidInternetGatewayID.NotFound": "target",
  "InvalidNatGatewayID.NotFound": "target",
  "InvalidVpcPeeringConnectionID.NotFound": "target",
  "InvalidTransitGatewayID.NotFound": "target",
  "InvalidNetworkInterfaceID.NotFound": "target",
  "InvalidInstanceID.NotFound": "target",
  "InvalidVpcEndpointId.NotFound": "target",
  "InvalidEgressOnlyInternetGatewayId.NotFound": "target",
  "InvalidCarrierGatewayID.NotFound": "target",
};

function routeTargetFrom(form: FormData) {
  const target = required(form, "target", "Target");
  const key = targetKey(target);
  if (!key) throw new FieldError("target", "Not a gateway, NAT, peering, transit gateway, interface, instance or endpoint ID", "pattern");
  return { [key]: target };
}

export async function addRoute(table: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const destination = required(form, "destination", "Destination");
    await (await ec2()).send(new CreateRouteCommand({ RouteTableId: table, [destinationOf(destination)]: destination, ...routeTargetFrom(form) }));
    return `Route to ${destination} added`;
  }, { revalidate: PAGES, fields: ROUTE_FIELDS });
}

export async function replaceRoute(table: string, destination: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ec2()).send(new ReplaceRouteCommand({ RouteTableId: table, [destinationOf(destination)]: destination, ...routeTargetFrom(form) }));
    return `Route to ${destination} updated`;
  }, { revalidate: PAGES, fields: ROUTE_FIELDS });
}

export async function deleteRoute(table: string, destination: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteRouteCommand({ RouteTableId: table, [destinationOf(destination)]: destination }));
    return "Route deleted";
  }, ...PAGES);
}
