import { GetDomainAssociationCommand, ListBranchesCommand } from "@aws-sdk/client-amplify";
import { ListHostedZonesByNameCommand, Route53Client } from "@aws-sdk/client-route-53";
import { all, client, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CopyButton, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { BadgeCheck, Globe, Pencil, ShieldCheck, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { amplify, tone } from "../../../lib/clients";
import { deleteDomain, updateDomain } from "../actions";

export const metadata: Metadata = { title: "Custom domain" };

type Props = { searchParams: Promise<{ app?: string; name?: string }> };

const SETTLED = /^(AVAILABLE|FAILED)$/;

/** "name CNAME value" as AWS writes DNS records, split for copying. */
function Record({ value }: { value: string }) {
  const [name, type, ...rest] = value.trim().split(/\s+/);
  return (
    <span className="inline-icon">
      <code>{name}</code> <Pill>{type}</Pill> <code>{rest.join(" ")}</code>
      <CopyButton value={value} label="Copy record" />
    </span>
  );
}

export default async function Domain({ searchParams }: Props) {
  const { app = "", name = "" } = await searchParams;
  const back = { href: `/amplify/app?id=${app}`, label: "App" };
  const data = await load(async () => {
    const c = await amplify();
    const [d, branches] = await Promise.all([
      c.send(new GetDomainAssociationCommand({ appId: app, domainName: name })).then((r) => r.domainAssociation!),
      all((nextToken) => c.send(new ListBranchesCommand({ appId: app, nextToken })), (r) => r.branches, (r) => r.nextToken),
    ]);
    // The hosted zone the records go in, when this account has one.
    const zone = await (await client(Route53Client))
      .send(new ListHostedZonesByNameCommand({ DNSName: name, MaxItems: 1 }))
      .then((r) => r.HostedZones?.find((z) => z.Name?.replace(/\.$/, "") === name), () => undefined);
    return { d, branches, zone };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon="service/AmazonRoute53" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { d, branches, zone } = data.value;
  const verification = d.certificate?.certificateVerificationDNSRecord ?? d.certificateVerificationDNSRecord;
  const subs = d.subDomains ?? [];
  return (
    <Page
      title={d.domainName}
      icon="service/AmazonRoute53"
      back={back}
      subtitle={d.domainAssociationArn}
      actions={
        <>
          {zone && (
            <Link className="icon-button plain" href={`/route53/zone?id=${encodeURIComponent(zone.Id!.split("/").pop()!)}`} aria-label="Hosted zone" title="Hosted zone">
              <AwsIcon icon="service/AmazonRoute53" size={16} />
            </Link>
          )}
          <Sheet title="Edit domain" label="Edit domain" icon={<Pencil size={15} />} testId="edit-domain">
            <ActionForm action={updateDomain.bind(null, app, d.domainName!)} submit="Save" testId="edit-domain">
              <Field label="Sub-domains" hint={`One per line: prefix=branch (@ for the apex). Branches: ${branches.map((b) => b.branchName).join(", ")}`}>
                <textarea name="subDomains" rows={4} required defaultValue={subs.map((s) => `${s.subDomainSetting?.prefix || "@"}=${s.subDomainSetting?.branchName}`).join("\n")} />
              </Field>
              <label className="check">
                <input type="checkbox" name="autoSub" defaultChecked={!!d.enableAutoSubDomain} /> Sub-domain per new branch
              </label>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteDomain.bind(null, app, d.domainName!)} submit="Remove domain" icon={<Trash2 size={16} />} tone="danger" confirm={`Remove ${d.domainName}?`} />
        </>
      }
    >
      <LiveRefresh when={!SETTLED.test(d.domainStatus ?? "") || (!!d.updateStatus && !/COMPLETE|FAILED/.test(d.updateStatus))} />
      <Specs
        items={[
          { label: "Status", icon: <Globe size={15} />, value: <Status tone={tone(d.domainStatus)}>{d.domainStatus?.toLowerCase().replace(/_/g, " ") ?? ""}</Status> },
          d.updateStatus && { label: "Update", icon: <Globe size={15} />, value: d.updateStatus.toLowerCase().replace(/_/g, " ") },
          d.certificate?.type && { label: "Certificate", icon: <ShieldCheck size={15} />, value: d.certificate.type === "CUSTOM" ? "custom" : "Amplify managed" },
        ]}
      />
      {d.statusReason && d.domainStatus !== "AVAILABLE" && <ErrorNotice error={d.statusReason} />}
      {verification && d.domainStatus !== "AVAILABLE" && (
        <Section title="SSL verification record">
          <Record value={verification} />
        </Section>
      )}
      <Section title="Sub-domains" count={subs.length} plain>
        <List
          label="Sub-domains"
          rows={subs.map((s) => {
            const prefix = s.subDomainSetting?.prefix;
            return {
              key: prefix || "@",
              icon: s.verified ? <BadgeCheck size={18} /> : <Globe size={18} />,
              title: prefix ? `${prefix}.${d.domainName}` : d.domainName,
              subtitle: s.dnsRecord ? <Record value={s.dnsRecord} /> : undefined,
              href: `/amplify/branch?app=${app}&name=${encodeURIComponent(s.subDomainSetting?.branchName ?? "")}`,
              meta: (
                <>
                  <Pill>{s.subDomainSetting?.branchName}</Pill>
                  <Status tone={s.verified ? "good" : "warn"}>{s.verified ? "verified" : "pending"}</Status>
                </>
              ),
            };
          })}
        />
      </Section>
    </Page>
  );
}
