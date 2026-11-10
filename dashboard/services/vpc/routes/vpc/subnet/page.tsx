import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { Globe, MapPin, Network, Server, Settings2, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATE_TONE, nameTag } from "../../../lib/clients";
import { isPublic, label, listAcls, listSubnets, listTables, listVpcs, routeTarget, tableFor } from "../../../lib/vpc";
import { deleteSubnet, editSubnet, moveSubnetTable } from "../actions";
import { moveSubnetAcl } from "../network-actions";

export const metadata: Metadata = { title: "Subnet" };

type Props = { searchParams: Promise<{ id?: string }> };

export default async function SubnetPage({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/vpc?tab=subnets", label: "Subnets" };
  const data = await load(async () => {
    const [subnet] = await listSubnets(undefined, [id]);
    if (!subnet) throw new Error(`The subnet ID '${id}' does not exist`);
    const [vpcs, tables, acls] = await Promise.all([listVpcs([subnet.VpcId!]), listTables(subnet.VpcId), listAcls(subnet.VpcId)]);
    return { subnet, vpc: vpcs[0], tables, acls };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.privateSubnet} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { subnet: s, vpc, tables, acls } = data.value;
  const pub = isPublic(s, tables);
  const table = tableFor(s, tables);
  const explicit = table?.Associations?.some((a) => a.SubnetId === id);
  const acl = acls.find((a) => a.Associations?.some((x) => x.SubnetId === id));

  return (
    <Page
      title={nameTag(s) ?? id}
      icon={pub ? ICONS.publicSubnet : ICONS.privateSubnet}
      back={back}
      subtitle={s.SubnetArn}
      actions={
        <>
          <Sheet title="Edit subnet settings" label="Edit subnet settings" icon={<Settings2 size={15} />} testId="edit-subnet">
            <ActionForm action={editSubnet.bind(null, id)} submit="Save" testId="edit-subnet">
              <label className="check">
                <input type="checkbox" name="publicIp" defaultChecked={!!s.MapPublicIpOnLaunch} /> Auto-assign public IPv4 address
              </label>
            </ActionForm>
          </Sheet>
          <Sheet title="Edit route table association" label="Edit route table association" icon={<AwsIcon icon={ICONS.routeTable} size={18} />} testId="subnet-route-table">
            <SubnetTablePicker id={id} tables={tables.map((t) => ({ id: t.RouteTableId!, label: `${label(t, t.RouteTableId)}${t.Associations?.some((a) => a.Main) ? " · main" : ""}` }))} current={table?.RouteTableId} />
          </Sheet>
          <Sheet title="Edit network ACL association" label="Edit network ACL association" icon={<AwsIcon icon={ICONS.nacl} size={18} />} testId="subnet-acl">
            <SubnetAclPicker id={id} acls={acls.map((a) => ({ id: a.NetworkAclId!, label: `${label(a, a.NetworkAclId)}${a.IsDefault ? " · default" : ""}` }))} current={acl?.NetworkAclId} />
          </Sheet>
          <ActionForm action={deleteSubnet.bind(null, id, "/vpc?tab=subnets")} submit="Delete subnet" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${id}?`} testId="delete-subnet" />
        </>
      }
    >
      <Specs
        items={[
          { label: "IPv4 CIDR", icon: <Network size={15} />, value: s.CidrBlock },
          s.Ipv6CidrBlockAssociationSet?.[0] && { label: "IPv6 CIDR", icon: <Network size={15} />, value: s.Ipv6CidrBlockAssociationSet.map((a) => a.Ipv6CidrBlock).join(", ") },
          { label: "Availability Zone", icon: <MapPin size={15} />, value: `${s.AvailabilityZone}${s.AvailabilityZoneId ? ` (${s.AvailabilityZoneId})` : ""}` },
          { label: "Available IPv4 addresses", icon: <Server size={15} />, value: `${s.AvailableIpAddressCount} free` },
          { label: "State", icon: <Server size={15} />, value: <Status tone={STATE_TONE(s.State)}>{s.State ?? ""}</Status> },
          s.MapPublicIpOnLaunch && { label: "Auto-assign public IPv4", icon: <Globe size={15} />, value: "Public IPs on launch" },
          s.DefaultForAz && { label: "Default subnet", icon: <AwsIcon icon={ICONS.privateSubnet} size={16} />, value: "Default for AZ" },
        ]}
      />
      <Section title="Network" plain>
        <List
          label="Network"
          rows={[
            vpc && { key: "vpc", icon: <AwsIcon icon={ICONS.vpc} size={22} />, title: label(vpc, vpc.VpcId), subtitle: vpc.CidrBlock, href: `/vpc/${vpc.VpcId}` },
            table && {
              key: "rtb",
              icon: <AwsIcon icon={ICONS.routeTable} size={22} />,
              title: label(table, table.RouteTableId),
              subtitle: (table.Routes ?? []).map((r) => `${r.DestinationCidrBlock ?? r.DestinationIpv6CidrBlock ?? r.DestinationPrefixListId} → ${routeTarget(r)}`).join(" · "),
              href: `/vpc/rtb?id=${table.RouteTableId}`,
              meta: (
                <>
                  {!explicit && <Pill tone="info">Main (implicit)</Pill>}
                  <Pill tone={pub ? "good" : "neutral"}>{pub ? "Public" : "Private"}</Pill>
                </>
              ),
            },
            acl && {
              key: "acl",
              icon: <AwsIcon icon={ICONS.nacl} size={22} />,
              title: label(acl, acl.NetworkAclId),
              subtitle: `${acl.Entries?.filter((e) => e.RuleNumber !== 32767).length ?? 0} rules`,
              href: `/vpc/acl?id=${acl.NetworkAclId}`,
              meta: acl.IsDefault ? <Pill tone="info">Default</Pill> : undefined,
            },
          ].filter((x): x is NonNullable<typeof x> => !!x)}
        />
      </Section>
      <Tags tags={s.Tags} />
    </Page>
  );
}

type Pick = { id: string; label: string };

function SubnetTablePicker({ id, tables, current }: { id: string; tables: Pick[]; current?: string }) {
  return (
    <ActionForm action={moveSubnetTable.bind(null, id)} submit="Save" testId="subnet-route-table">
      <Field label="Route table">
        <select name="table" defaultValue={current}>
          {tables.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
      </Field>
    </ActionForm>
  );
}

function SubnetAclPicker({ id, acls, current }: { id: string; acls: Pick[]; current?: string }) {
  return (
    <ActionForm action={moveSubnetAcl.bind(null, id)} submit="Save" testId="subnet-acl">
      <Field label="Network ACL">
        <select name="acl" defaultValue={current}>
          {acls.map((a) => (
            <option key={a.id} value={a.id}>
              {a.label}
            </option>
          ))}
        </select>
      </Field>
    </ActionForm>
  );
}
