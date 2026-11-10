import { DescribeVpcPeeringConnectionsCommand, type VpcPeeringConnectionVpcInfo } from "@aws-sdk/client-ec2";
import { ago, load, region } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Facts, List, Page, Section, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { Clock, Globe, Settings2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATE_TONE, ec2, nameTag } from "../../../lib/clients";
import { label, listTables, listVpcs } from "../../../lib/vpc";
import { editPeeringDns } from "../network-actions";
import { PeeringActions } from "../tabs";

export const metadata: Metadata = { title: "Peering connection" };

type Props = { searchParams: Promise<{ id?: string }> };

export default async function PeeringPage({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/vpc?tab=peering", label: "Peering connections" };
  const data = await load(async () => {
    const p = (await (await ec2()).send(new DescribeVpcPeeringConnectionsCommand({ VpcPeeringConnectionIds: [id] }))).VpcPeeringConnections?.[0];
    if (!p) throw new Error(`The vpcPeeringConnection ID '${id}' does not exist`);
    const [vpcs, tables, here] = await Promise.all([listVpcs(), listTables(), region()]);
    return { p, vpcs, tables: tables.filter((t) => t.Routes?.some((r) => r.VpcPeeringConnectionId === id)), here };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.peering} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { p, vpcs, tables, here } = data.value;
  const code = p.Status?.Code;
  const mine = (info: VpcPeeringConnectionVpcInfo | undefined) => vpcs.some((v) => v.VpcId === info?.VpcId) && (info?.Region ?? here) === here;
  const side = (title: string, info: VpcPeeringConnectionVpcInfo | undefined, key: "requester" | "accepter") => {
    const own = mine(info);
    const v = vpcs.find((x) => x.VpcId === info?.VpcId);
    return (
      <Section
        title={title}
        actions={
          own && code === "active" ? (
            <Sheet title={`${title} DNS`} label={`Edit ${key} DNS settings`} icon={<Settings2 size={15} />} testId={`peering-dns-${key}`}>
              <ActionForm action={editPeeringDns.bind(null, id, key)} submit="Save" testId={`peering-dns-${key}`}>
                <label className="check">
                  <input type="checkbox" name="dns" defaultChecked={!!info?.PeeringOptions?.AllowDnsResolutionFromRemoteVpc} /> Allow the other VPC to resolve DNS of hosts in this VPC to private IP addresses
                </label>
              </ActionForm>
            </Sheet>
          ) : undefined
        }
      >
        <Facts
          items={[
            ["VPC", own ? <Link href={`/vpc/${info?.VpcId}`}>{label(v, info?.VpcId)}</Link> : info?.VpcId],
            ["CIDRs", (info?.CidrBlockSet ?? []).map((c) => c.CidrBlock).join(", ") || info?.CidrBlock],
            (info?.Ipv6CidrBlockSet?.length ?? 0) > 0 && ["IPv6 CIDRs", info!.Ipv6CidrBlockSet!.map((c) => c.Ipv6CidrBlock).join(", ")],
            ["Account", info?.OwnerId],
            ["Region", info?.Region ?? here],
            code === "active" && ["DNS resolution from the other VPC", info?.PeeringOptions?.AllowDnsResolutionFromRemoteVpc ? "Allowed" : "Not allowed"],
          ]}
        />
      </Section>
    );
  };
  return (
    <Page
      title={nameTag(p) ?? id}
      icon={ICONS.peering}
      back={back}
      subtitle={nameTag(p) ? id : undefined}
      actions={<PeeringActions id={id} code={code} accepter={mine(p.AccepterVpcInfo)} />}
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.peering} size={16} />, value: <Status tone={STATE_TONE(code)}>{code ?? ""}</Status> },
          p.Status?.Message && { label: "Message", icon: <Globe size={15} />, value: p.Status.Message },
          p.ExpirationTime && code === "pending-acceptance" && { label: "Expires", icon: <Clock size={15} />, value: ago(p.ExpirationTime) },
        ]}
      />
      {side("Requester", p.RequesterVpcInfo, "requester")}
      {side("Accepter", p.AccepterVpcInfo, "accepter")}
      {tables.length > 0 && (
        <Section title="Route tables" count={tables.length} plain>
          <List
            label="Route tables"
            rows={tables.map((t) => ({
              key: t.RouteTableId!,
              icon: <AwsIcon icon={ICONS.routeTable} size={20} />,
              title: label(t, t.RouteTableId),
              subtitle: (t.Routes ?? []).filter((r) => r.VpcPeeringConnectionId === id).map((r) => r.DestinationCidrBlock ?? r.DestinationIpv6CidrBlock).join(", "),
              href: `/vpc/rtb?id=${t.RouteTableId}`,
            }))}
          />
        </Section>
      )}
      <Tags tags={p.Tags} />
    </Page>
  );
}
