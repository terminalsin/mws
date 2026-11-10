import { GetHostedZoneCommand, ListResourceRecordSetsCommand, type ResourceRecordSet } from "@aws-sdk/client-route-53";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Page, Pill, Sheet, Specs } from "@mws-dashboard/ui";
import { Hash, Lock, Pencil, Plus, Server, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, route53 } from "../../../lib/clients";
import { RecordFields } from "../../../lib/record-fields";
import { deleteRecord, deleteZone, saveRecord } from "../actions";

export const metadata: Metadata = { title: "Hosted zone" };

type Props = { searchParams: Promise<{ id?: string }> };

/** What a record does, so the zone reads by purpose: where traffic goes,
 * where mail goes, and the zone's own plumbing. */
function purpose(r: ResourceRecordSet) {
  if (r.Type === "NS" || r.Type === "SOA" || r.Type === "DS") return "zone";
  if (r.Type === "MX" || (r.Type === "TXT" && r.ResourceRecords?.some((v) => /v=spf1|v=DKIM1|v=DMARC1/i.test(v.Value ?? ""))) || /(_domainkey|_dmarc)\./.test(r.Name ?? "")) return "mail";
  if (r.Type === "CNAME" && /^_[0-9a-f]{32}\./.test(r.Name ?? "")) return "validation";
  if (r.Type === "TXT") return "verification";
  return "traffic";
}

function RecordForm({ zone, record, domain, names }: { zone: string; record?: ResourceRecordSet; domain: string; names: string[] }) {
  const testId = record ? `edit-record-${record.Name}-${record.Type}` : "create-record";
  return (
    <ActionForm action={saveRecord.bind(null, zone)} submit={record ? "Save record" : "Create record"} testId={testId}>
      <RecordFields
        zone={domain}
        names={names}
        defaults={{
          name: record?.Name?.replace(/\.$/, "").replace(/\\052/g, "*") ?? domain,
          type: record?.Type ?? "A",
          values: record?.ResourceRecords?.map((v) => v.Value).join("\n") ?? "",
          ttl: record?.TTL ?? 300,
          alias: record?.AliasTarget?.DNSName,
          aliasZone: record?.AliasTarget?.HostedZoneId,
        }}
      />
    </ActionForm>
  );
}

export default async function HostedZone({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/route53", label: "Hosted zones" };
  const data = await load(async () => {
    const client = await route53();
    const [zone, records] = await Promise.all([
      client.send(new GetHostedZoneCommand({ Id: id })),
      client.send(new ListResourceRecordSetsCommand({ HostedZoneId: id, MaxItems: 300 })).then((r) => r.ResourceRecordSets ?? []),
    ]);
    return { zone, records };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.zone} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { zone, records } = data.value;
  const domain = zone.HostedZone!.Name!.replace(/\.$/, "");
  const names = [...new Set(records.filter((r) => !r.AliasTarget && r.Type !== "NS" && r.Type !== "SOA").map((r) => r.Name!.replace(/\.$/, "")))];
  const sections = [
    { id: "traffic", title: "Traffic", items: records.filter((r) => purpose(r) === "traffic") },
    { id: "mail", title: "Mail", items: records.filter((r) => purpose(r) === "mail") },
    { id: "verification", title: "Verification", items: records.filter((r) => purpose(r) === "verification" || purpose(r) === "validation") },
    { id: "zone", title: "Zone", items: records.filter((r) => purpose(r) === "zone") },
  ];
  return (
    <Page
      title={domain}
      icon={ICONS.zone}
      back={back}
      subtitle={id}
      actions={
        <>
          <Sheet title="Create record" label="Create record" icon={<Plus size={16} />} testId="create-record">
            <RecordForm zone={id} domain={domain} names={names} />
          </Sheet>
          <ActionForm action={deleteZone.bind(null, id)} submit="Delete hosted zone" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${domain}?`} testId="delete-zone" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Type", icon: zone.HostedZone?.Config?.PrivateZone ? <Lock size={15} /> : <AwsIcon icon={ICONS.internet} size={16} />, value: zone.HostedZone?.Config?.PrivateZone ? "Private" : "Public" },
          { label: "Records", icon: <Hash size={15} />, value: zone.HostedZone?.ResourceRecordSetCount },
          ...(zone.VPCs ?? []).map((v) => ({ label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <Link href={`/vpc/${v.VPCId}`}>{v.VPCId}</Link> })),
          zone.DelegationSet?.NameServers?.length && { label: "Name servers", icon: <Server size={15} />, value: zone.DelegationSet.NameServers.join(" ") },
        ]}
      />
      <Curated
        label="Records"
        sections={sections}
        empty={<Empty icon={ICONS.zone} />}
        row={(r) => {
          const name = r.Name!.replace(/\.$/, "").replace(/\\052/g, "*");
          const value = r.AliasTarget ? r.AliasTarget.DNSName?.replace(/\.$/, "") : r.ResourceRecords?.map((v) => v.Value).join(", ");
          const locked = (r.Type === "NS" || r.Type === "SOA") && name === domain;
          return {
            key: `${r.Name}-${r.Type}-${r.SetIdentifier ?? ""}`,
            icon: <Pill tone={r.AliasTarget ? "info" : "neutral"}>{r.Type}</Pill>,
            title: name === domain ? <span>{name}</span> : <span>{name.slice(0, -domain.length - 1)}<span className="muted">.{domain}</span></span>,
            subtitle: <code className="clip">{value}</code>,
            meta: (
              <>
                {r.AliasTarget && <Pill tone="info">Alias</Pill>}
                {r.SetIdentifier && <Pill>{r.Weight !== undefined ? `weight ${r.Weight}` : r.Region ?? r.Failover ?? r.SetIdentifier}</Pill>}
                {r.TTL !== undefined && <span title="TTL">{r.TTL}s</span>}
              </>
            ),
            actions: locked ? undefined : (
              <>
                <Sheet title="Edit record" label={`Edit ${name} ${r.Type}`} icon={<Pencil size={15} />} testId={`edit-record-${r.Name}-${r.Type}`}>
                  <RecordForm zone={id} record={r} domain={domain} names={names} />
                </Sheet>
                <ActionForm action={deleteRecord.bind(null, id, r)} submit={`Delete ${name} ${r.Type}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${name} ${r.Type}?`} />
              </>
            ),
          };
        }}
      />
    </Page>
  );
}
