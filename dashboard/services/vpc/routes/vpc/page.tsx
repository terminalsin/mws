import {
  DescribeAvailabilityZonesCommand,
  DescribeInternetGatewaysCommand,
  DescribeNatGatewaysCommand,
  DescribeNetworkAclsCommand,
  DescribeVpcEndpointsCommand,
  DescribeVpcPeeringConnectionsCommand,
} from "@aws-sdk/client-ec2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ec2, nameTag } from "../../lib/clients";
import { SubnetFields, VpcFields } from "../../lib/forms";
import { choices, cidrsOf, isPublic, network, routeTarget } from "../../lib/vpc";
import { createSubnet, createVpc, deleteEndpoint, deleteInternetGateway, deleteNatGateway, deleteSubnet } from "./actions";

export const metadata: Metadata = { title: "VPC" };

type Props = { searchParams: Promise<{ tab?: string }> };

const TITLES: Record<string, string> = {
  vpcs: "Your VPCs",
  subnets: "Subnets",
  routes: "Route tables",
  igw: "Internet gateways",
  nat: "NAT gateways",
  endpoints: "Endpoints",
  peering: "Peering connections",
  acls: "Network ACLs",
};

const STATE_TONE = (s: string | undefined) => (s === "available" || s === "active" || s === "attached" ? "good" : s === "failed" || s === "rejected" || s === "deleted" ? "bad" : "warn");

function CreateVpc({ used }: { used: string[] }) {
  return (
    <Sheet title="Create VPC" label="Create VPC" testId="create-vpc">
      <ActionForm action={createVpc} submit="Create VPC" testId="create-vpc">
        <VpcFields used={used} />
      </ActionForm>
    </Sheet>
  );
}

export default async function Vpcs({ searchParams }: Props) {
  const { tab = "vpcs" } = await searchParams;
  const title = TITLES[tab] ?? TITLES.vpcs;
  const net = await load(() => network());
  if (!net.ok) {
    return (
      <Page title={title}>
        <ErrorNotice error={net.error} />
      </Page>
    );
  }
  const { vpcs, subnets, tables } = net.value;
  const vpcName = (id: string | undefined) => {
    const v = vpcs.find((x) => x.VpcId === id);
    return v ? (nameTag(v) ?? v.VpcId) : id;
  };
  const client = await ec2();
  const used = vpcs.flatMap(cidrsOf);
  let body;
  let actions = <CreateVpc used={used} />;

  if (tab === "subnets") {
    const zones = await load(async () => (await client.send(new DescribeAvailabilityZonesCommand({}))).AvailabilityZones ?? []);
    actions = (
      <Sheet title="Create subnet" label="Create subnet" testId="create-subnet">
        <ActionForm action={createSubnet} submit="Create subnet" testId="create-subnet">
          <SubnetFields vpcs={choices(vpcs, subnets)} zones={zones.ok ? zones.value.map((z) => z.ZoneName!) : []} />
        </ActionForm>
      </Sheet>
    );
    body = (
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
          title: nameTag(s) ?? s.SubnetId,
          subtitle: `${s.CidrBlock} · ${vpcName(s.VpcId)}`,
          href: `/vpc/${s.VpcId}`,
          meta: (
            <>
              <Pill>{s.AvailabilityZone}</Pill>
              <span title="Available IPv4 addresses">{s.AvailableIpAddressCount} free</span>
            </>
          ),
          actions: s.DefaultForAz ? undefined : (
            <ActionForm action={deleteSubnet.bind(null, s.SubnetId!)} submit={`Delete ${s.SubnetId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.SubnetId}?`} />
          ),
        })}
      />
    );
  } else if (tab === "routes") {
    body = (
      <List
        label="Route tables"
        empty={<Empty icon={ICONS.routeTable} />}
        rows={tables.map((t) => {
          const main = t.Associations?.some((a) => a.Main);
          const explicit = t.Associations?.filter((a) => a.SubnetId).length ?? 0;
          const internet = t.Routes?.find((r) => r.DestinationCidrBlock === "0.0.0.0/0");
          return {
            key: t.RouteTableId!,
            icon: <AwsIcon icon={ICONS.routeTable} size={24} />,
            title: nameTag(t) ?? t.RouteTableId,
            subtitle: vpcName(t.VpcId),
            href: `/vpc/${t.VpcId}#${t.RouteTableId}`,
            meta: (
              <>
                {main && <Pill tone="info">Main</Pill>}
                {internet && <Pill title="0.0.0.0/0">→ {routeTarget(internet)}</Pill>}
                {explicit > 0 && <span>{explicit} subnets</span>}
              </>
            ),
          };
        })}
      />
    );
  } else if (tab === "igw") {
    const igws = await load(async () => (await client.send(new DescribeInternetGatewaysCommand({}))).InternetGateways ?? []);
    body = igws.ok ? (
      <List
        label="Internet gateways"
        empty={<Empty icon={ICONS.igw} />}
        rows={igws.value.map((g) => {
          const vpc = g.Attachments?.[0]?.VpcId;
          return {
            key: g.InternetGatewayId!,
            icon: <AwsIcon icon={ICONS.igw} size={24} />,
            title: nameTag(g) ?? g.InternetGatewayId,
            subtitle: vpc ? vpcName(vpc) : undefined,
            href: vpc ? `/vpc/${vpc}` : undefined,
            meta: <Status tone={vpc ? "good" : "neutral"}>{vpc ? "Attached" : "Detached"}</Status>,
            actions: (
              <ActionForm action={deleteInternetGateway.bind(null, g.InternetGatewayId!, vpc)} submit={`Delete ${g.InternetGatewayId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Detach and delete ${g.InternetGatewayId}?`} />
            ),
          };
        })}
      />
    ) : (
      <ErrorNotice error={igws.error} />
    );
  } else if (tab === "nat") {
    const nats = await load(async () => (await client.send(new DescribeNatGatewaysCommand({}))).NatGateways ?? []);
    body = nats.ok ? (
      <List
        label="NAT gateways"
        empty={<Empty icon={ICONS.nat} />}
        rows={nats.value.map((n) => ({
          key: n.NatGatewayId!,
          icon: <AwsIcon icon={ICONS.nat} size={24} />,
          title: nameTag(n) ?? n.NatGatewayId,
          subtitle: `${n.NatGatewayAddresses?.[0]?.PublicIp ?? n.NatGatewayAddresses?.[0]?.PrivateIp ?? ""} · ${vpcName(n.VpcId)}`,
          href: `/vpc/${n.VpcId}`,
          meta: (
            <>
              {n.ConnectivityType === "private" && <Pill>Private</Pill>}
              <Status tone={STATE_TONE(n.State)}>{n.State}</Status>
            </>
          ),
          actions:
            n.State === "available" ? (
              <ActionForm action={deleteNatGateway.bind(null, n.NatGatewayId!)} submit={`Delete ${n.NatGatewayId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${n.NatGatewayId}?`} />
            ) : undefined,
        }))}
      />
    ) : (
      <ErrorNotice error={nats.error} />
    );
  } else if (tab === "endpoints") {
    const eps = await load(async () => (await client.send(new DescribeVpcEndpointsCommand({}))).VpcEndpoints ?? []);
    body = eps.ok ? (
      <Curated
        label="Endpoints"
        sections={[
          { id: "Interface", title: "Interface", items: eps.value.filter((e) => e.VpcEndpointType === "Interface") },
          { id: "Gateway", title: "Gateway", items: eps.value.filter((e) => e.VpcEndpointType !== "Interface") },
        ]}
        empty={<Empty icon={ICONS.endpoint} />}
        row={(e) => ({
          key: e.VpcEndpointId!,
          icon: <AwsIcon icon={ICONS.endpoint} size={24} />,
          title: e.ServiceName,
          subtitle: `${e.VpcEndpointId} · ${vpcName(e.VpcId)}`,
          href: `/vpc/${e.VpcId}`,
          meta: <Status tone={STATE_TONE(e.State?.toLowerCase())}>{e.State}</Status>,
          actions: <ActionForm action={deleteEndpoint.bind(null, e.VpcEndpointId!)} submit={`Delete ${e.VpcEndpointId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${e.VpcEndpointId}?`} />,
        })}
      />
    ) : (
      <ErrorNotice error={eps.error} />
    );
  } else if (tab === "peering") {
    const pcx = await load(async () => (await client.send(new DescribeVpcPeeringConnectionsCommand({}))).VpcPeeringConnections ?? []);
    body = pcx.ok ? (
      <List
        label="Peering connections"
        empty={<Empty icon={ICONS.peering} />}
        rows={pcx.value.map((p) => ({
          key: p.VpcPeeringConnectionId!,
          icon: <AwsIcon icon={ICONS.peering} size={24} />,
          title: nameTag(p) ?? p.VpcPeeringConnectionId,
          subtitle: `${p.RequesterVpcInfo?.CidrBlock} ⇄ ${p.AccepterVpcInfo?.CidrBlock}`,
          meta: <Status tone={STATE_TONE(p.Status?.Code)}>{p.Status?.Code}</Status>,
        }))}
      />
    ) : (
      <ErrorNotice error={pcx.error} />
    );
  } else if (tab === "acls") {
    const acls = await load(async () => (await client.send(new DescribeNetworkAclsCommand({}))).NetworkAcls ?? []);
    body = acls.ok ? (
      <List
        label="Network ACLs"
        empty={<Empty icon={ICONS.nacl} />}
        rows={acls.value.map((a) => ({
          key: a.NetworkAclId!,
          icon: <AwsIcon icon={ICONS.nacl} size={24} />,
          title: nameTag(a) ?? a.NetworkAclId,
          subtitle: vpcName(a.VpcId),
          href: `/vpc/${a.VpcId}`,
          meta: (
            <>
              {a.IsDefault && <Pill tone="info">Default</Pill>}
              <span>{a.Entries?.filter((e) => e.RuleNumber !== 32767).length ?? 0} rules</span>
              <span>{a.Associations?.length ?? 0} subnets</span>
            </>
          ),
        }))}
      />
    ) : (
      <ErrorNotice error={acls.error} />
    );
  } else {
    body = (
      <List
        label="VPCs"
        empty={<Empty icon={ICONS.vpc} action={<CreateVpc used={used} />} />}
        rows={vpcs.map((v) => {
          const own = subnets.filter((s) => s.VpcId === v.VpcId);
          const pub = own.filter((s) => isPublic(s, tables)).length;
          return {
            key: v.VpcId!,
            icon: <AwsIcon icon={ICONS.vpc} size={24} />,
            title: nameTag(v) ?? v.VpcId,
            subtitle: `${v.CidrBlock}${nameTag(v) ? ` · ${v.VpcId}` : ""}`,
            href: `/vpc/${v.VpcId}`,
            meta: (
              <>
                {v.IsDefault && <Pill tone="info">Default</Pill>}
                {own.length > 0 && (
                  <span title={`${pub} public, ${own.length - pub} private`}>
                    {own.length} subnets
                  </span>
                )}
                <Status tone={STATE_TONE(v.State)}>{v.State}</Status>
              </>
            ),
          };
        })}
      />
    );
  }
  return (
    <Page title={title} actions={actions}>
      {body}
    </Page>
  );
}
