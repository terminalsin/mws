import { DescribeVpcEndpointsCommand } from "@aws-sdk/client-ec2";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { ModifyVpcEndpoint } from "@mws-dashboard/ui/model/ec2";
import { Calendar, FileText, Globe, Network, Settings2, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATE_TONE, ec2, nameTag } from "../../../lib/clients";
import { knownService } from "../../../lib/endpoint-services";
import { EndpointNetworkFields } from "../../../lib/network-forms";
import { label, listGroups, network } from "../../../lib/vpc";
import { deleteEndpoint, editEndpointNetwork, editEndpointPolicy } from "../network-actions";
import { networkChoices } from "../tabs";

export const metadata: Metadata = { title: "Endpoint" };

function pretty(doc: string | undefined) {
  if (!doc) return "";
  try {
    return JSON.stringify(JSON.parse(doc), null, 2);
  } catch {
    return doc;
  }
}

type Props = { searchParams: Promise<{ id?: string; tab?: string }> };

export default async function EndpointPage({ searchParams }: Props) {
  const { id = "", tab = "details" } = await searchParams;
  const base = `/vpc/endpoint?id=${id}`;
  const back = { href: "/vpc?tab=endpoints", label: "Endpoints" };
  const data = await load(async () => {
    const ep = (await (await ec2()).send(new DescribeVpcEndpointsCommand({ VpcEndpointIds: [id] }))).VpcEndpoints?.[0];
    if (!ep) throw new Error(`The Vpc Endpoint Id '${id}' does not exist`);
    const [net, groups] = await Promise.all([network(ep.VpcId), listGroups(ep.VpcId)]);
    const [vpc] = await networkChoices(net, groups);
    return { ep, net, vpc };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.endpoint} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { ep, net, vpc } = data.value;
  const gateway = ep.VpcEndpointType === "Gateway";
  const state = ep.State?.toLowerCase() ?? "";
  const subnetName = (s: string) => label(net.subnets.find((x) => x.SubnetId === s), s);
  const tableName = (t: string) => label(net.tables.find((x) => x.RouteTableId === t), t);

  let body;
  if (tab === "policy") {
    body = (
      <Section
        title="Policy"
        actions={
          <Sheet title="Edit policy" label="Edit policy" icon={<FileText size={15} />} testId="edit-endpoint-policy">
            <ActionForm action={editEndpointPolicy.bind(null, id)} submit="Save" testId="edit-endpoint-policy">
              <Field label="Policy" rule={{ ...ModifyVpcEndpoint.PolicyDocument, format: "policy", required: false }} member="PolicyDocument" hint="Full access when empty">
                <textarea name="policy" rows={14} spellCheck={false} defaultValue={pretty(ep.PolicyDocument)} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        <CodeBlock value={ep.PolicyDocument} label="Endpoint policy" />
      </Section>
    );
  } else if (gateway) {
    body = (
      <List
        label="Route tables"
        empty={<Empty icon={ICONS.routeTable} />}
        rows={(ep.RouteTableIds ?? []).map((t) => ({ key: t, icon: <AwsIcon icon={ICONS.routeTable} size={20} />, title: tableName(t), subtitle: t, href: `/vpc/rtb?id=${t}` }))}
      />
    );
  } else {
    body = (
      <>
        <Section title="DNS names" count={ep.DnsEntries?.length} plain>
          <List
            label="DNS names"
            rows={(ep.DnsEntries ?? []).map((d) => ({ key: d.DnsName!, icon: <Globe size={18} />, title: <code>{d.DnsName}</code>, subtitle: d.HostedZoneId }))}
          />
        </Section>
        <Section title="Subnets" count={ep.SubnetIds?.length} plain>
          <List
            label="Subnets"
            rows={(ep.SubnetIds ?? []).map((s) => ({
              key: s,
              icon: <AwsIcon icon={ICONS.privateSubnet} size={20} />,
              title: subnetName(s),
              subtitle: net.subnets.find((x) => x.SubnetId === s)?.AvailabilityZone,
              href: `/vpc/subnet?id=${s}`,
              meta: ep.NetworkInterfaceIds?.length ? <span>{ep.NetworkInterfaceIds.length} interfaces</span> : undefined,
            }))}
          />
        </Section>
        <Section title="Security groups" count={ep.Groups?.length} plain>
          <List
            label="Security groups"
            rows={(ep.Groups ?? []).map((g) => ({ key: g.GroupId!, icon: <AwsIcon icon={ICONS.nacl} size={20} />, title: g.GroupName, subtitle: g.GroupId, href: `/ec2/group?id=${g.GroupId}` }))}
          />
        </Section>
      </>
    );
  }

  return (
    <Page
      title={nameTag(ep) ?? id}
      icon={knownService(ep.ServiceName)?.icon ?? ICONS.endpoint}
      back={back}
      subtitle={nameTag(ep) ? id : undefined}
      actions={
        <>
          {vpc && (
            <Sheet title={gateway ? "Manage route tables" : "Manage subnets and security groups"} label={gateway ? "Manage route tables" : "Manage subnets"} icon={<Settings2 size={15} />} testId="edit-endpoint">
              <ActionForm action={editEndpointNetwork.bind(null, id)} submit="Save" testId="edit-endpoint">
                <EndpointNetworkFields
                  type={ep.VpcEndpointType ?? "Gateway"}
                  vpc={vpc}
                  tables={ep.RouteTableIds ?? []}
                  subnets={ep.SubnetIds ?? []}
                  groups={(ep.Groups ?? []).map((g) => g.GroupId!)}
                  privateDns={!!ep.PrivateDnsEnabled}
                />
              </ActionForm>
            </Sheet>
          )}
          <ActionForm action={deleteEndpoint.bind(null, id, "/vpc?tab=endpoints")} submit="Delete endpoint" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${id}?`} testId="delete-endpoint" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Service", icon: <AwsIcon icon={ICONS.endpoint} size={16} />, value: ep.ServiceName },
          { label: "Type", icon: <Network size={15} />, value: <Pill>{ep.VpcEndpointType}</Pill> },
          { label: "State", icon: <Network size={15} />, value: <Status tone={STATE_TONE(state)}>{state}</Status> },
          { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <Link href={`/vpc/${ep.VpcId}`}>{vpc?.label ?? ep.VpcId}</Link> },
          !gateway && { label: "Private DNS", icon: <Globe size={15} />, value: ep.PrivateDnsEnabled ? "Private DNS on" : "Private DNS off" },
          ep.IpAddressType && { label: "IP address type", icon: <Network size={15} />, value: ep.IpAddressType },
          { label: "Created", icon: <Calendar size={15} />, value: when(ep.CreationTimestamp) },
        ]}
      />
      {ep.LastError?.Message && <ErrorNotice error={`${ep.LastError.Code}: ${ep.LastError.Message}`} />}
      <Segments
        items={[
          { label: gateway ? "Route tables" : "Subnets", href: base, active: tab !== "policy", count: (gateway ? ep.RouteTableIds?.length : ep.SubnetIds?.length) || undefined },
          { label: "Policy", href: `${base}&tab=policy`, active: tab === "policy" },
        ]}
      />
      {body}
      <Tags tags={ep.Tags} />
    </Page>
  );
}
