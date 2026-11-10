import type { NetworkAclEntry } from "@aws-sdk/client-ec2";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Section, Segments, Sheet, Specs, Tags } from "@mws-dashboard/ui";
import { ArrowDownToLine, ArrowUpFromLine, Ban, Check, Pencil, Plus, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { LAST_RULE, portsOf, protocolName } from "../../../lib/acl";
import { ICONS, nameTag } from "../../../lib/clients";
import { AclEntryFields } from "../../../lib/network-forms";
import { label, listAcls, listSubnets, listVpcs } from "../../../lib/vpc";
import { addAclEntry, deleteAcl, deleteAclEntry, editAclSubnets, replaceAclEntry } from "../network-actions";

export const metadata: Metadata = { title: "Network ACL" };

type Props = { searchParams: Promise<{ id?: string; tab?: string }> };

export default async function AclPage({ searchParams }: Props) {
  const { id = "", tab = "inbound" } = await searchParams;
  const base = `/vpc/acl?id=${id}`;
  const back = { href: "/vpc?tab=acls", label: "Network ACLs" };
  const data = await load(async () => {
    const all = await listAcls();
    const acl = all.find((a) => a.NetworkAclId === id);
    if (!acl) throw new Error(`The networkAcl ID '${id}' does not exist`);
    const [vpcs, subnets] = await Promise.all([listVpcs([acl.VpcId!]), listSubnets(acl.VpcId)]);
    return { acl, acls: all.filter((a) => a.VpcId === acl.VpcId), vpc: vpcs[0], subnets };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.nacl} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { acl, acls, vpc, subnets } = data.value;
  const egress = tab === "outbound";
  const entries = (acl.Entries ?? []).filter((e) => !!e.Egress === egress).sort((a, b) => (a.RuleNumber ?? 0) - (b.RuleNumber ?? 0));
  const taken = (acl.Entries ?? []).filter((e) => !!e.Egress === egress).map((e) => String(e.RuleNumber));
  const associated = new Set((acl.Associations ?? []).map((a) => a.SubnetId));
  const aclOf = (s: string | undefined) => acls.find((a) => a.Associations?.some((x) => x.SubnetId === s));
  const count = (out: boolean) => (acl.Entries ?? []).filter((e) => !!e.Egress === out && e.RuleNumber !== LAST_RULE).length;

  const entryRow = (e: NetworkAclEntry) => {
    const n = e.RuleNumber!;
    const deny = e.RuleAction === "deny";
    const cidr = e.CidrBlock ?? e.Ipv6CidrBlock ?? "";
    const ports = portsOf(e);
    const last = n === LAST_RULE;
    return {
      key: `${n}-${cidr}`,
      icon: deny ? <Ban size={18} className="bad" /> : <Check size={18} />,
      title: (
        <>
          <code>{last ? "*" : n}</code> {protocolName(e.Protocol)}
          {ports && ports !== "All" ? ` ${ports}` : ""}
        </>
      ),
      subtitle: `${egress ? "to" : "from"} ${cidr}`,
      meta: <Pill tone={deny ? "bad" : "good"}>{deny ? "Deny" : "Allow"}</Pill>,
      actions: last ? undefined : (
        <>
          <Sheet title={`Edit rule ${n}`} label={`Edit rule ${n}`} icon={<Pencil size={15} />}>
            <ActionForm action={replaceAclEntry.bind(null, id, egress, n)} submit="Save">
              <AclEntryFields taken={[]} entry={{ number: n, egress, protocol: e.Protocol ?? "-1", ports, cidr, action: e.RuleAction ?? "allow" }} />
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteAclEntry.bind(null, id, egress, n)} submit={`Delete rule ${n}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${egress ? "outbound" : "inbound"} rule ${n}?`} />
        </>
      ),
    };
  };

  let body;
  if (tab === "subnets") {
    body = (
      <Section
        title="Subnet associations"
        count={associated.size}
        plain
        actions={
          <Sheet title="Edit subnet associations" label="Edit subnet associations" icon={<Pencil size={15} />} testId="edit-acl-subnets">
            <ActionForm action={editAclSubnets.bind(null, id, acl.VpcId!)} submit="Save associations" testId="edit-acl-subnets">
              <fieldset className="checks">
                <legend>Subnets</legend>
                {subnets.map((s) => {
                  const other = aclOf(s.SubnetId);
                  return (
                    <label key={s.SubnetId} className="check">
                      <input type="checkbox" name="subnet" value={s.SubnetId} defaultChecked={associated.has(s.SubnetId)} disabled={acl.IsDefault && associated.has(s.SubnetId)} /> {label(s, s.SubnetId)} · {s.CidrBlock}
                      {other && other.NetworkAclId !== id && <Pill>{label(other, other.NetworkAclId)}</Pill>}
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
          rows={subnets
            .filter((s) => associated.has(s.SubnetId))
            .map((s) => ({ key: s.SubnetId!, icon: <AwsIcon icon={ICONS.privateSubnet} size={20} />, title: label(s, s.SubnetId), subtitle: s.CidrBlock, href: `/vpc/subnet?id=${s.SubnetId}` }))}
        />
      </Section>
    );
  } else {
    body = (
      <Section
        title={egress ? "Outbound rules" : "Inbound rules"}
        count={entries.length}
        plain
        actions={
          <Sheet title={`Add ${egress ? "outbound" : "inbound"} rule`} label="Add rule" icon={<Plus size={16} />} testId="add-acl-rule">
            <ActionForm action={addAclEntry.bind(null, id)} submit="Add rule" testId="add-acl-rule">
              <input type="hidden" name="direction" value={egress ? "outbound" : "inbound"} />
              <AclEntryFields taken={taken} />
            </ActionForm>
          </Sheet>
        }
      >
        <List label={egress ? "Outbound rules" : "Inbound rules"} rows={entries.map(entryRow)} />
      </Section>
    );
  }

  return (
    <Page
      title={nameTag(acl) ?? id}
      icon={ICONS.nacl}
      back={back}
      subtitle={nameTag(acl) ? id : undefined}
      actions={
        !acl.IsDefault ? <ActionForm action={deleteAcl.bind(null, id, "/vpc?tab=acls")} submit="Delete network ACL" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${id}?`} testId="delete-acl" /> : undefined
      }
    >
      <Specs
        items={[
          vpc && { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <Link href={`/vpc/${vpc.VpcId}`}>{label(vpc, vpc.VpcId)}</Link> },
          acl.IsDefault && { label: "Default", icon: <AwsIcon icon={ICONS.nacl} size={16} />, value: "Default ACL" },
          { label: "Inbound rules", icon: <ArrowDownToLine size={15} />, value: `${count(false)} in` },
          { label: "Outbound rules", icon: <ArrowUpFromLine size={15} />, value: `${count(true)} out` },
        ]}
      />
      <Segments
        items={[
          { label: "Inbound rules", href: base, active: tab === "inbound", count: count(false) },
          { label: "Outbound rules", href: `${base}&tab=outbound`, active: tab === "outbound", count: count(true) },
          { label: "Subnet associations", href: `${base}&tab=subnets`, active: tab === "subnets", count: associated.size || undefined },
        ]}
      />
      {body}
      <Tags tags={acl.Tags} />
    </Page>
  );
}
