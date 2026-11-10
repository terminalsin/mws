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
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ec2 } from "../../lib/clients";

const tags = (type: "vpc" | "subnet" | "internet-gateway" | "route-table" | "natgateway", name: string) =>
  name ? [{ ResourceType: type, Tags: [{ Key: "Name", Value: name }] }] : undefined;

/** Split a /16 into /20s: the n-th block. */
function block(cidr: string, n: number) {
  const [ip, bits] = cidr.split("/");
  const octets = ip.split(".").map(Number);
  const value = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const size = Math.max(Number(bits) + 4, 20);
  const next = (value + n * 2 ** (32 - size)) >>> 0;
  return `${[next >>> 24, (next >>> 16) & 255, (next >>> 8) & 255, next & 255].join(".")}/${size}`;
}

export async function createVpc(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = text(form, "name");
    const cidr = required(form, "cidr", "IPv4 CIDR");
    const client = await ec2();
    const vpc = (await client.send(new CreateVpcCommand({ CidrBlock: cidr, TagSpecifications: tags("vpc", name) }))).Vpc!;
    const VpcId = vpc.VpcId!;
    await client.send(new ModifyVpcAttributeCommand({ VpcId, EnableDnsHostnames: { Value: true } }));
    if (text(form, "layout") === "public-private") {
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
              new CreateSubnetCommand({ VpcId, AvailabilityZone: az, CidrBlock: block(cidr, n++), TagSpecifications: tags("subnet", `${name || VpcId}-subnet-${kind}-${az}`) }),
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
  });
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
    await (await ec2()).send(
      new CreateSubnetCommand({
        VpcId,
        CidrBlock: required(form, "cidr", "IPv4 CIDR"),
        AvailabilityZone: text(form, "az") || undefined,
        TagSpecifications: tags("subnet", text(form, "name")),
      }),
    );
    return "Subnet created";
  }, "/vpc", `/vpc/${text(form, "vpc")}`);
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
  }, "/vpc", "/vpc/[id]");
}

export async function deleteRoute(table: string, destination: string) {
  return act(async () => {
    await (await ec2()).send(new DeleteRouteCommand({ RouteTableId: table, DestinationCidrBlock: destination }));
    return "Route deleted";
  }, "/vpc", "/vpc/[id]");
}
