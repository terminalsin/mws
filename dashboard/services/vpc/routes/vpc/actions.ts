"use server";

import {
  AssociateRouteTableCommand,
  AttachInternetGatewayCommand,
  CreateInternetGatewayCommand,
  CreateNatGatewayCommand,
  CreateRouteCommand,
  CreateRouteTableCommand,
  CreateSubnetCommand,
  CreateVpcCommand,
  DeleteInternetGatewayCommand,
  DeleteNatGatewayCommand,
  DeleteRouteCommand,
  DeleteSubnetCommand,
  DeleteVpcCommand,
  DeleteVpcEndpointsCommand,
  DescribeAvailabilityZonesCommand,
  DetachInternetGatewayCommand,
  ModifySubnetAttributeCommand,
  ModifyVpcAttributeCommand,
  AllocateAddressCommand,
} from "@aws-sdk/client-ec2";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ec2 } from "../../lib/clients";

const tags = (type: "vpc" | "subnet" | "internet-gateway" | "route-table" | "natgateway", name: string) =>
  name ? [{ ResourceType: type, Tags: [{ Key: "Name", Value: name }] }] : undefined;

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

export async function createVpc(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = text(form, "name");
    const block = required(form, "cidr", "IPv4 CIDR");
    const client = await ec2();
    const layout = text(form, "layout");
    // Four subnets of at least /28 need a /26 or larger.
    if (layout === "public-private" && Number(block.split("/")[1]) > 26) throw new FieldError("cidr", "Netmask /16 to /26 for four subnets");
    const vpc = (await cidr(() => client.send(new CreateVpcCommand({ CidrBlock: block, TagSpecifications: tags("vpc", name) })))).Vpc!;
    const VpcId = vpc.VpcId!;
    await client.send(new ModifyVpcAttributeCommand({ VpcId, EnableDnsHostnames: { Value: true } }));
    if (layout === "public-private") {
      // "VPC and more": a public and a private subnet in each of two zones,
      // an internet gateway, and a public route table.
      const zones = ((await client.send(new DescribeAvailabilityZonesCommand({}))).AvailabilityZones ?? []).slice(0, 2).map((z) => z.ZoneName!);
      const igw = (await client.send(new CreateInternetGatewayCommand({ TagSpecifications: tags("internet-gateway", name && `${name}-igw`) }))).InternetGateway!;
      await client.send(new AttachInternetGatewayCommand({ VpcId, InternetGatewayId: igw.InternetGatewayId! }));
      const rt = (await client.send(new CreateRouteTableCommand({ VpcId, TagSpecifications: tags("route-table", name && `${name}-rtb-public`) }))).RouteTable!;
      await client.send(new CreateRouteCommand({ RouteTableId: rt.RouteTableId!, DestinationCidrBlock: "0.0.0.0/0", GatewayId: igw.InternetGatewayId! }));
      let n = 0;
      for (const kind of ["public", "private"]) {
        for (const az of zones) {
          const subnet = (
            await client.send(
              new CreateSubnetCommand({ VpcId, AvailabilityZone: az, CidrBlock: split(block, n++), TagSpecifications: tags("subnet", `${name || VpcId}-subnet-${kind}-${az}`) }),
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

export async function deleteVpc(id: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteVpcCommand({ VpcId: id }));
    redirect("/vpc");
  });
}

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
          TagSpecifications: tags("subnet", text(form, "name")),
        }),
      ),
    );
    return "Subnet created";
  }, { revalidate: ["/vpc", `/vpc/${text(form, "vpc")}`], fields: { CidrBlock: "cidr", AvailabilityZone: "az", "InvalidVpcID.NotFound": "vpc" } });
}

export async function deleteSubnet(id: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteSubnetCommand({ SubnetId: id }));
    return "Subnet deleted";
  }, "/vpc", "/vpc/[id]");
}

export async function createInternetGateway(vpc: string) {
  return act(async () => {
    const client = await ec2();
    const igw = (await client.send(new CreateInternetGatewayCommand({}))).InternetGateway!;
    await client.send(new AttachInternetGatewayCommand({ VpcId: vpc, InternetGatewayId: igw.InternetGatewayId! }));
    return `Attached ${igw.InternetGatewayId}`;
  }, "/vpc", `/vpc/${vpc}`);
}

export async function deleteInternetGateway(id: string, vpc: string | undefined) {
  return act(async () => {
    const client = await ec2();
    if (vpc) await client.send(new DetachInternetGatewayCommand({ InternetGatewayId: id, VpcId: vpc }));
    await client.send(new DeleteInternetGatewayCommand({ InternetGatewayId: id }));
    return "Internet gateway deleted";
  }, "/vpc", "/vpc/[id]");
}

export async function createNatGateway(subnet: string) {
  return act(async () => {
    const client = await ec2();
    const eip = await client.send(new AllocateAddressCommand({ Domain: "vpc" }));
    const nat = (await client.send(new CreateNatGatewayCommand({ SubnetId: subnet, AllocationId: eip.AllocationId }))).NatGateway!;
    return `Created ${nat.NatGatewayId}`;
  }, "/vpc", "/vpc/[id]");
}

export async function deleteNatGateway(id: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteNatGatewayCommand({ NatGatewayId: id }));
    return "NAT gateway deleting";
  }, "/vpc", "/vpc/[id]");
}

export async function deleteEndpoint(id: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteVpcEndpointsCommand({ VpcEndpointIds: [id] }));
    return "Endpoint deleted";
  }, "/vpc");
}

export async function addRoute(table: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const target = required(form, "target", "Target");
    const DestinationCidrBlock = required(form, "destination", "Destination");
    const key = target.startsWith("igw-") ? "GatewayId" : target.startsWith("nat-") ? "NatGatewayId" : target.startsWith("pcx-") ? "VpcPeeringConnectionId" : target.startsWith("tgw-") ? "TransitGatewayId" : target.startsWith("eni-") ? "NetworkInterfaceId" : "GatewayId";
    await (await ec2()).send(new CreateRouteCommand({ RouteTableId: table, DestinationCidrBlock, [key]: target }));
    return `Route to ${DestinationCidrBlock} added`;
  }, {
    revalidate: ["/vpc", "/vpc/[id]"],
    fields: {
      DestinationCidrBlock: "destination",
      RouteAlreadyExists: "destination",
      "InvalidGatewayID.NotFound": "target",
      "InvalidInternetGatewayID.NotFound": "target",
      "InvalidNatGatewayID.NotFound": "target",
      "InvalidVpcPeeringConnectionID.NotFound": "target",
      "InvalidTransitGatewayID.NotFound": "target",
      "InvalidNetworkInterfaceID.NotFound": "target",
    },
  });
}

export async function deleteRoute(table: string, destination: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteRouteCommand({ RouteTableId: table, DestinationCidrBlock: destination }));
    return "Route deleted";
  }, "/vpc", "/vpc/[id]");
}
