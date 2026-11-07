import { DescribeInternetGatewaysCommand, DescribeNatGatewaysCommand, DescribeSecurityGroupsCommand, DescribeVpcEndpointsCommand } from "@aws-sdk/client-ec2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status, Tags, zoneHref } from "@mws-dashboard/ui";
import { Globe, Network, Plus, Server, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ec2, nameTag } from "../../../lib/clients";
import { isPublic, network, routeTarget, tableFor } from "../../../lib/vpc";
import { addRoute, createInternetGateway, createNatGateway, deleteRoute, deleteVpc } from "../actions";

type Props = { params: Promise<{ id: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: (await params).id };
}

export default async function Vpc({ params }: Props) {
  const { id } = await params;
  const back = { href: "/vpc", label: "Your VPCs" };
  const data = await load(async () => {
    const client = await ec2();
    const Filters = [{ Name: "vpc-id", Values: [id] }];
    const [net, igws, nats, endpoints, groups] = await Promise.all([
      network(id),
      client.send(new DescribeInternetGatewaysCommand({ Filters: [{ Name: "attachment.vpc-id", Values: [id] }] })).then((r) => r.InternetGateways ?? []),
      client.send(new DescribeNatGatewaysCommand({ Filter: Filters })).then((r) => (r.NatGateways ?? []).filter((n) => n.State !== "deleted")),
      client.send(new DescribeVpcEndpointsCommand({ Filters })).then((r) => r.VpcEndpoints ?? []),
      client.send(new DescribeSecurityGroupsCommand({ Filters })).then((r) => r.SecurityGroups ?? []),
    ]);
    return { ...net, igws, nats, endpoints, groups };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.vpc} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { vpcs, subnets, tables, igws, nats, endpoints, groups } = data.value;
  const vpc = vpcs[0];
  const name = nameTag(vpc) ?? id;
  const publicSubnet = subnets.find((s) => isPublic(s, tables));
  const zones = [...new Set(subnets.map((s) => s.AvailabilityZone!))].sort();
  const subnetName = (sid: string | undefined) => nameTag(subnets.find((s) => s.SubnetId === sid) ?? {}) ?? sid;

  return (
    <Page
      title={name}
      icon={ICONS.vpc}
      back={back}
      subtitle={nameTag(vpc) ? id : undefined}
      actions={
        <>
          {igws.length === 0 && <ActionForm action={createInternetGateway.bind(null, id)} submit="Attach internet gateway" icon={<Globe size={16} />} />}
          {publicSubnet && <ActionForm action={createNatGateway.bind(null, publicSubnet.SubnetId!)} submit="Create NAT gateway" icon={<AwsIcon icon={ICONS.nat} size={18} />} />}
          {!vpc.IsDefault && <ActionForm action={deleteVpc.bind(null, id)} submit="Delete VPC" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-vpc" />}
        </>
      }
    >
      <Specs
        items={[
          { label: "IPv4 CIDR", icon: <Network size={15} />, value: [vpc.CidrBlock, ...(vpc.CidrBlockAssociationSet ?? []).map((c) => c.CidrBlock).filter((c) => c !== vpc.CidrBlock)].join(", ") },
          vpc.Ipv6CidrBlockAssociationSet?.[0] && { label: "IPv6 CIDR", icon: <Network size={15} />, value: vpc.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock },
          { label: "State", icon: <Server size={15} />, value: <Status tone={vpc.State === "available" ? "good" : "warn"}>{vpc.State}</Status> },
          vpc.IsDefault && { label: "Default VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: "Default" },
          vpc.InstanceTenancy === "dedicated" && { label: "Tenancy", icon: <Server size={15} />, value: "Dedicated" },
        ]}
      />

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
                    <div key={s.SubnetId} className={`map-node ${isPublic(s, tables) ? "public" : "private"}`} title={s.CidrBlock}>
                      <AwsIcon icon={isPublic(s, tables) ? ICONS.publicSubnet : ICONS.privateSubnet} size={18} />
                      <span>{nameTag(s) ?? s.SubnetId}</span>
                    </div>
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
              Network connections <span className="count">{igws.length + nats.length + endpoints.length}</span>
            </h3>
            {igws.map((g) => (
              <div key={g.InternetGatewayId} className="map-node">
                <AwsIcon icon={ICONS.igw} size={18} />
                <span>{nameTag(g) ?? g.InternetGatewayId}</span>
              </div>
            ))}
            {nats.map((n) => (
              <div key={n.NatGatewayId} className="map-node">
                <AwsIcon icon={ICONS.nat} size={18} />
                <span>{nameTag(n) ?? n.NatGatewayId}</span>
                {n.State !== "available" && <Status tone="warn">{n.State}</Status>}
              </div>
            ))}
            {endpoints.map((e) => (
              <div key={e.VpcEndpointId} className="map-node">
                <AwsIcon icon={ICONS.endpoint} size={18} />
                <span>{e.ServiceName?.split(".").pop()}</span>
              </div>
            ))}
          </div>
        </div>
      </Section>

      {tables.map((t) => {
        const subnetsHere = subnets.filter((s) => tableFor(s, tables)?.RouteTableId === t.RouteTableId);
        const targets = [...igws.map((g) => g.InternetGatewayId!), ...nats.map((n) => n.NatGatewayId!)];
        return (
          <div key={t.RouteTableId} id={t.RouteTableId}>
            <Section
              title={nameTag(t) ?? t.RouteTableId}
              icon={<AwsIcon icon={ICONS.routeTable} size={18} />}
              count={t.Routes?.length}
              plain
              actions={
                <Sheet title="Add route" label={`Add route to ${t.RouteTableId}`} icon={<Plus size={16} />} testId={`add-route-${t.RouteTableId}`}>
                  <ActionForm action={addRoute.bind(null, t.RouteTableId!)} submit="Add route" testId={`add-route-${t.RouteTableId}`}>
                    <Field label="Destination">
                      <input name="destination" required defaultValue="0.0.0.0/0" />
                    </Field>
                    <Field label="Target">
                      <input name="target" required list={`targets-${t.RouteTableId}`} defaultValue={targets[0]} />
                    </Field>
                    <datalist id={`targets-${t.RouteTableId}`}>
                      {targets.map((x) => (
                        <option key={x} value={x} />
                      ))}
                    </datalist>
                  </ActionForm>
                </Sheet>
              }
            >
              <List
                label={`Routes of ${t.RouteTableId}`}
                rows={(t.Routes ?? []).map((r) => {
                  const dest = r.DestinationCidrBlock ?? r.DestinationIpv6CidrBlock ?? r.DestinationPrefixListId ?? "";
                  const target = routeTarget(r);
                  const icon = target.startsWith("igw-") ? ICONS.internet : target.startsWith("nat-") ? ICONS.nat : target.startsWith("vpce-") ? ICONS.endpoint : target.startsWith("pcx-") ? ICONS.peering : ICONS.vpc;
                  return {
                    key: dest,
                    icon: <AwsIcon icon={icon} size={20} />,
                    title: <code>{dest}</code>,
                    subtitle: target,
                    meta: r.State === "blackhole" ? <Status tone="bad">Blackhole</Status> : undefined,
                    actions:
                      target !== "local" && r.DestinationCidrBlock ? (
                        <ActionForm action={deleteRoute.bind(null, t.RouteTableId!, r.DestinationCidrBlock)} submit={`Delete route ${dest}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete the route to ${dest}?`} />
                      ) : undefined,
                  };
                })}
              />
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
              href: `${zoneHref("compute", "/ec2")}?tab=groups`,
              external: true,
              meta: <span>{(g.IpPermissions?.length ?? 0) + (g.IpPermissionsEgress?.length ?? 0)} rules</span>,
            }))}
          />
        </Section>
      )}
      <Tags tags={vpc.Tags} />
    </Page>
  );
}
