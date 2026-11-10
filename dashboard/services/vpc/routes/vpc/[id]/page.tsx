import { DescribeAvailabilityZonesCommand, DescribeVpcAttributeCommand } from "@aws-sdk/client-ec2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { AssociateVpcCidrBlock } from "@mws-dashboard/ui/model/ec2";
import { Globe, Network, Plus, Server, Settings2, Trash2, X } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATE_TONE, ec2, nameTag } from "../../../lib/clients";
import { SubnetFields } from "../../../lib/forms";
import { AddRoute, Routes } from "../../../lib/route-table";
import { routeTargets } from "../../../lib/targets";
import { choices, isPublic, label, listEndpoints, listGroups, listIgws, listNats, listPeerings, network, tableFor } from "../../../lib/vpc";
import { addVpcCidr, attachNewInternetGateway, createSubnet, deleteVpc, editVpcDns, removeVpcCidr } from "../actions";
import { CreateRouteTableSheet, deleteVpcConfirm, natSheet } from "../tabs";

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: (await params).id };
}

export default async function Vpc({ params }: Props) {
  const { id } = await params;
  const back = { href: "/vpc", label: "Your VPCs" };
  const data = await load(async () => {
    const client = await ec2();
    const attr = (Attribute: "enableDnsSupport" | "enableDnsHostnames") => client.send(new DescribeVpcAttributeCommand({ VpcId: id, Attribute })).catch(() => undefined);
    const [net, igws, nats, endpoints, groups, zones, peerings, targets, dns, hostnames] = await Promise.all([
      network(id),
      listIgws(id),
      listNats(id).then((n) => n.filter((x) => x.State !== "deleted")),
      listEndpoints(id),
      listGroups(id),
      client.send(new DescribeAvailabilityZonesCommand({})).then((r) => (r.AvailabilityZones ?? []).map((z) => z.ZoneName!)),
      listPeerings().then((all) => all.filter((p) => p.Status?.Code !== "deleted" && p.Status?.Code !== "rejected" && (p.RequesterVpcInfo?.VpcId === id || p.AccepterVpcInfo?.VpcId === id))),
      routeTargets(id),
      attr("enableDnsSupport"),
      attr("enableDnsHostnames"),
    ]);
    return { ...net, igws, nats, endpoints, groups, zones, peerings, targets: targets.targets, dns: dns?.EnableDnsSupport?.Value, hostnames: hostnames?.EnableDnsHostnames?.Value };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.vpc} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { vpcs, subnets, tables, igws, nats, endpoints, groups, zones: allZones, peerings, targets, dns, hostnames } = data.value;
  const vpc = vpcs[0];
  if (!vpc) {
    return (
      <Page title={id} icon={ICONS.vpc} back={back}>
        <ErrorNotice error={`The vpc ID '${id}' does not exist`} />
      </Page>
    );
  }
  const name = nameTag(vpc) ?? id;
  const zones = [...new Set(subnets.map((s) => s.AvailabilityZone!))].sort();
  const subnetName = (sid: string | undefined) => label(subnets.find((s) => s.SubnetId === sid), sid);
  const v4 = vpc.CidrBlockAssociationSet ?? [];
  const v6 = vpc.Ipv6CidrBlockAssociationSet ?? [];
  const blocks = [
    ...v4.filter((c) => c.CidrBlockState?.State !== "disassociated").map((c) => ({ id: c.AssociationId!, cidr: c.CidrBlock!, state: c.CidrBlockState?.State, primary: c.CidrBlock === vpc.CidrBlock })),
    ...v6.filter((c) => c.Ipv6CidrBlockState?.State !== "disassociated").map((c) => ({ id: c.AssociationId!, cidr: c.Ipv6CidrBlock ?? "IPv6", state: c.Ipv6CidrBlockState?.State, primary: false })),
  ];
  const nat = await natSheet(subnets, tables);

  return (
    <Page
      title={name}
      icon={ICONS.vpc}
      back={back}
      subtitle={nameTag(vpc) ? id : undefined}
      actions={
        <>
          <Sheet title="Create subnet" label="Create subnet" icon={<Plus size={16} />} testId="create-subnet">
            <ActionForm action={createSubnet} submit="Create subnet" testId="create-subnet">
              <SubnetFields vpcs={choices(vpcs, subnets)} zones={allZones} vpc={id} />
            </ActionForm>
          </Sheet>
          <CreateRouteTableSheet vpcs={vpcs} vpc={id} />
          {igws.length === 0 && (
            <ActionForm action={attachNewInternetGateway.bind(null, id)} submit="Attach internet gateway" icon={<Globe size={16} />} />
          )}
          {subnets.length > 0 && nat}
          <Sheet title="Edit DNS settings" label="Edit VPC settings" icon={<Settings2 size={15} />} testId="edit-vpc-dns">
            <ActionForm action={editVpcDns.bind(null, id)} submit="Save" testId="edit-vpc-dns">
              <label className="check">
                <input type="checkbox" name="support" defaultChecked={dns !== false} /> Enable DNS resolution
              </label>
              <label className="check">
                <input type="checkbox" name="hostnames" defaultChecked={!!hostnames} /> Enable DNS hostnames
              </label>
            </ActionForm>
          </Sheet>
          <Sheet title="Add CIDR" label="Edit CIDRs" icon={<Network size={15} />} testId="add-cidr">
            <ActionForm action={addVpcCidr.bind(null, id)} submit="Add CIDR" testId="add-cidr">
              <Field label="IPv4 CIDR" rule={{ ...AssociateVpcCidrBlock.CidrBlock, format: "cidr", cidr: { prefix: [16, 28], avoid: blocks.map((b) => b.cidr).filter((c) => !c.includes(":")) } }} member="CidrBlock">
                <input name="cidr" spellCheck={false} />
              </Field>
              <label className="check">
                <input type="checkbox" name="ipv6" /> Amazon-provided IPv6 CIDR block instead
              </label>
            </ActionForm>
          </Sheet>
          {!vpc.IsDefault && <ActionForm action={deleteVpc.bind(null, id)} submit="Delete VPC" icon={<Trash2 size={16} />} tone="danger" confirm={deleteVpcConfirm(name)} testId="delete-vpc" />}
        </>
      }
    >
      <Specs
        items={[
          { label: "IPv4 CIDR", icon: <Network size={15} />, value: blocks.filter((b) => !b.cidr.includes(":")).map((b) => b.cidr).join(", ") },
          v6[0] && { label: "IPv6 CIDR", icon: <Network size={15} />, value: v6.map((c) => c.Ipv6CidrBlock).filter(Boolean).join(", ") },
          { label: "State", icon: <Server size={15} />, value: <Status tone={STATE_TONE(vpc.State)}>{vpc.State ?? ""}</Status> },
          { label: "DNS", icon: <Globe size={15} />, value: `${dns === false ? "No DNS resolution" : "DNS resolution"}${hostnames ? " · hostnames" : ""}` },
          vpc.DhcpOptionsId && { label: "DHCP option set", icon: <Settings2 size={15} />, value: vpc.DhcpOptionsId },
          vpc.IsDefault && { label: "Default VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: "Default" },
          vpc.InstanceTenancy === "dedicated" && { label: "Tenancy", icon: <Server size={15} />, value: "Dedicated" },
        ]}
      />

      {blocks.length > 1 && (
        <Section title="CIDRs" count={blocks.length} plain>
          <List
            label="CIDRs"
            rows={blocks.map((b) => ({
              key: b.id,
              icon: <Network size={18} />,
              title: <code>{b.cidr}</code>,
              meta: (
                <>
                  {b.primary && <Pill tone="info">Primary</Pill>}
                  <Status tone={STATE_TONE(b.state)}>{b.state ?? ""}</Status>
                </>
              ),
              actions: b.primary ? undefined : <ActionForm action={removeVpcCidr.bind(null, b.id)} submit={`Remove ${b.cidr}`} icon={<X size={15} />} tone="danger" confirm={`Disassociate ${b.cidr}?`} />,
            }))}
          />
        </Section>
      )}

      <Section title="Resource map">
        <div className="resource-map" aria-label="Resource map">
          <div className="map-column">
            <h3>
              Subnets <span className="count">{subnets.length}</span>
            </h3>
            {zones.map((az) => (
              <div key={az} className="map-group">
                <div className="map-group-title">{az}</div>
                {subnets
                  .filter((s) => s.AvailabilityZone === az)
                  .map((s) => (
                    <Link key={s.SubnetId} className={`map-node ${isPublic(s, tables) ? "public" : "private"}`} title={s.CidrBlock} href={`/vpc/subnet?id=${s.SubnetId}`}>
                      <AwsIcon icon={isPublic(s, tables) ? ICONS.publicSubnet : ICONS.privateSubnet} size={18} />
                      <span>{nameTag(s) ?? s.SubnetId}</span>
                    </Link>
                  ))}
              </div>
            ))}
          </div>
          <div className="map-column">
            <h3>
              Route tables <span className="count">{tables.length}</span>
            </h3>
            {tables.map((t) => (
              <a key={t.RouteTableId} className="map-node" href={`#${t.RouteTableId}`}>
                <AwsIcon icon={ICONS.routeTable} size={18} />
                <span>{nameTag(t) ?? t.RouteTableId}</span>
                {t.Associations?.some((a) => a.Main) && <Pill tone="info">Main</Pill>}
              </a>
            ))}
          </div>
          <div className="map-column">
            <h3>
              Network connections <span className="count">{igws.length + nats.length + endpoints.length + peerings.length}</span>
            </h3>
            {igws.map((g) => (
              <Link key={g.InternetGatewayId} className="map-node" href="/vpc?tab=igw">
                <AwsIcon icon={ICONS.igw} size={18} />
                <span>{nameTag(g) ?? g.InternetGatewayId}</span>
              </Link>
            ))}
            {nats.map((n) => (
              <Link key={n.NatGatewayId} className="map-node" href="/vpc?tab=nat">
                <AwsIcon icon={ICONS.nat} size={18} />
                <span>{nameTag(n) ?? n.NatGatewayId}</span>
                {n.State !== "available" && <Status tone={STATE_TONE(n.State)}>{n.State ?? ""}</Status>}
              </Link>
            ))}
            {endpoints.map((e) => (
              <Link key={e.VpcEndpointId} className="map-node" href={`/vpc/endpoint?id=${e.VpcEndpointId}`}>
                <AwsIcon icon={ICONS.endpoint} size={18} />
                <span>{nameTag(e) ?? e.ServiceName?.split(".").pop()}</span>
              </Link>
            ))}
            {peerings.map((p) => (
              <Link key={p.VpcPeeringConnectionId} className="map-node" href={`/vpc/peering?id=${p.VpcPeeringConnectionId}`}>
                <AwsIcon icon={ICONS.peering} size={18} />
                <span>{nameTag(p) ?? p.VpcPeeringConnectionId}</span>
                {p.Status?.Code !== "active" && <Status tone={STATE_TONE(p.Status?.Code)}>{p.Status?.Code ?? ""}</Status>}
              </Link>
            ))}
          </div>
        </div>
      </Section>

      {tables.map((t) => {
        const subnetsHere = subnets.filter((s) => tableFor(s, tables)?.RouteTableId === t.RouteTableId);
        return (
          <div key={t.RouteTableId} id={t.RouteTableId}>
            <Section
              title={<Link href={`/vpc/rtb?id=${t.RouteTableId}`}>{nameTag(t) ?? t.RouteTableId}</Link>}
              icon={<AwsIcon icon={ICONS.routeTable} size={18} />}
              count={t.Routes?.length}
              plain
              actions={<AddRoute table={t} targets={targets} />}
            >
              <Routes table={t} targets={targets} />
              {subnetsHere.length > 0 && <div className="muted route-subnets">{subnetsHere.map((s) => subnetName(s.SubnetId)).join(" · ")}</div>}
            </Section>
          </div>
        );
      })}

      {groups.length > 0 && (
        <Section title="Security groups" count={groups.length} plain>
          <List
            label="Security groups"
            rows={groups.map((g) => ({
              key: g.GroupId!,
              icon: <AwsIcon icon={ICONS.nacl} size={20} />,
              title: g.GroupName,
              subtitle: g.Description,
              href: `/ec2/group?id=${g.GroupId}`,
              meta: <span>{(g.IpPermissions?.length ?? 0) + (g.IpPermissionsEgress?.length ?? 0)} rules</span>,
            }))}
          />
        </Section>
      )}
      <Tags tags={vpc.Tags} />
    </Page>
  );
}
