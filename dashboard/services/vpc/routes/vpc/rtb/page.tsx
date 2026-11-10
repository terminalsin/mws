import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Section, Segments, Sheet, Specs, Tags } from "@mws-dashboard/ui";
import { Crown, Network, Pencil, Radio, RadioTower, Trash2, Unlink } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, nameTag } from "../../../lib/clients";
import { AddRoute, Routes } from "../../../lib/route-table";
import { routeTargets } from "../../../lib/targets";
import { label, listSubnets, listTables, listVpcs, tableFor } from "../../../lib/vpc";
import { deleteRouteTable, disassociateTable, editTableSubnets, setMainTable, setPropagation } from "../actions";

export const metadata: Metadata = { title: "Route table" };

type Props = { searchParams: Promise<{ id?: string; tab?: string }> };

export default async function RouteTablePage({ searchParams }: Props) {
  const { id = "", tab = "routes" } = await searchParams;
  const base = `/vpc/rtb?id=${id}`;
  const back = { href: "/vpc?tab=routes", label: "Route tables" };
  const data = await load(async () => {
    const all = await listTables();
    const table = all.find((t) => t.RouteTableId === id);
    if (!table) throw new Error(`The routeTable ID '${id}' does not exist`);
    const vpcId = table.VpcId!;
    const [vpcs, subnets, targets] = await Promise.all([listVpcs([vpcId]), listSubnets(vpcId), routeTargets(vpcId)]);
    return { table, tables: all.filter((t) => t.VpcId === vpcId), vpc: vpcs[0], subnets, ...targets };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.routeTable} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { table: t, tables, vpc, subnets, targets, vgws } = data.value;
  const vpcId = t.VpcId!;
  const main = t.Associations?.some((a) => a.Main);
  const explicit = (t.Associations ?? []).filter((a) => a.SubnetId);
  const implicit = main ? subnets.filter((s) => !tables.some((x) => x.Associations?.some((a) => a.SubnetId === s.SubnetId))) : [];
  const propagating = new Set((t.PropagatingVgws ?? []).map((p) => p.GatewayId));
  const subnetName = (sid: string | undefined) => label(subnets.find((s) => s.SubnetId === sid), sid);

  let body;
  if (tab === "subnets") {
    body = (
      <Section
        title="Explicit subnet associations"
        count={explicit.length}
        plain
        actions={
          <Sheet title="Edit subnet associations" label="Edit subnet associations" icon={<Pencil size={15} />} testId="edit-associations">
            <ActionForm action={editTableSubnets.bind(null, id, vpcId)} submit="Save associations" testId="edit-associations">
              <fieldset className="checks">
                <legend>Subnets</legend>
                {subnets.map((s) => {
                  const other = tableFor(s, tables);
                  return (
                    <label key={s.SubnetId} className="check">
                      <input type="checkbox" name="subnet" value={s.SubnetId} defaultChecked={explicit.some((a) => a.SubnetId === s.SubnetId)} /> {label(s, s.SubnetId)} · {s.CidrBlock}
                      {other && other.RouteTableId !== id && <Pill>{label(other, other.RouteTableId)}</Pill>}
                    </label>
                  );
                })}
              </fieldset>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Subnet associations"
          empty={<Empty icon={ICONS.privateSubnet} />}
          rows={[
            ...explicit.map((a) => ({
              key: a.RouteTableAssociationId!,
              icon: <AwsIcon icon={ICONS.privateSubnet} size={20} />,
              title: subnetName(a.SubnetId),
              subtitle: subnets.find((s) => s.SubnetId === a.SubnetId)?.CidrBlock,
              href: `/vpc/subnet?id=${a.SubnetId}`,
              actions: (
                <ActionForm action={disassociateTable.bind(null, a.RouteTableAssociationId!)} submit={`Disassociate ${a.SubnetId}`} icon={<Unlink size={15} />} confirm={`Move ${a.SubnetId} back to the main route table?`} />
              ),
            })),
            ...implicit.map((s) => ({
              key: s.SubnetId!,
              icon: <AwsIcon icon={ICONS.privateSubnet} size={20} />,
              title: label(s, s.SubnetId),
              subtitle: s.CidrBlock,
              href: `/vpc/subnet?id=${s.SubnetId}`,
              meta: <Pill tone="info">Implicit</Pill>,
            })),
          ]}
        />
      </Section>
    );
  } else if (tab === "propagation") {
    body = (
      <List
        label="Route propagation"
        empty={<Empty icon={ICONS.vgw} />}
        rows={vgws.map((g) => {
          const on = propagating.has(g);
          return {
            key: g,
            icon: <AwsIcon icon={ICONS.vgw} size={20} />,
            title: g,
            meta: <Pill tone={on ? "good" : "neutral"}>{on ? "Propagating" : "Off"}</Pill>,
            actions: (
              <ActionForm action={setPropagation.bind(null, id, g, !on)} submit={on ? `Disable propagation from ${g}` : `Enable propagation from ${g}`} icon={on ? <Radio size={15} /> : <RadioTower size={15} />} />
            ),
          };
        })}
      />
    );
  } else {
    body = (
      <Section title="Routes" count={t.Routes?.length} plain actions={<AddRoute table={t} targets={targets} />}>
        <Routes table={t} targets={targets} />
      </Section>
    );
  }

  return (
    <Page
      title={nameTag(t) ?? id}
      icon={ICONS.routeTable}
      back={back}
      subtitle={nameTag(t) ? id : undefined}
      actions={
        <>
          {!main && <ActionForm action={setMainTable.bind(null, id, vpcId)} submit="Set main route table" icon={<Crown size={16} />} confirm={`Make ${id} the main route table of ${vpcId}?`} testId="set-main" />}
          {!main && <ActionForm action={deleteRouteTable.bind(null, id, "/vpc?tab=routes")} submit="Delete route table" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${id}?`} testId="delete-route-table" />}
        </>
      }
    >
      <Specs
        items={[
          vpc && { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <Link href={`/vpc/${vpcId}`}>{label(vpc, vpcId)}</Link> },
          main && { label: "Main", icon: <Crown size={15} />, value: "Main route table" },
          { label: "Subnets", icon: <Network size={15} />, value: `${explicit.length + implicit.length} subnets` },
          t.OwnerId && { label: "Owner", icon: <Network size={15} />, value: t.OwnerId },
        ]}
      />
      <Segments
        items={[
          { label: "Routes", href: base, active: tab === "routes", count: t.Routes?.length },
          { label: "Subnet associations", href: `${base}&tab=subnets`, active: tab === "subnets", count: explicit.length + implicit.length || undefined },
          { label: "Route propagation", href: `${base}&tab=propagation`, active: tab === "propagation", count: vgws.length || undefined },
        ]}
      />
      {body}
      <Tags tags={t.Tags} />
    </Page>
  );
}
