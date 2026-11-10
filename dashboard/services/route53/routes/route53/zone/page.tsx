import { DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { DescribeKeyCommand, ListKeysCommand } from "@aws-sdk/client-kms";
import {
  GetDNSSECCommand,
  GetHostedZoneCommand,
  ListQueryLoggingConfigsCommand,
  ListResourceRecordSetsCommand,
  ListTagsForResourceCommand,
  ListVPCAssociationAuthorizationsCommand,
  type ResourceRecordSet,
  type RRType,
} from "@aws-sdk/client-route-53";
import { load, region } from "@mws-dashboard/aws";
import { ActionForm, AutoPick, AwsIcon, CodeBlock, Curated, Empty, ErrorNotice, Field, List, More, Page, Pill, Section, Segments, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { FlaskConical, Hash, HeartPulse, KeyRound, Lock, Pause, Pencil, Play, Plus, ScrollText, Server, ShieldCheck, Tag, Trash2, X } from "lucide-react";
import {
  AssociateVPCWithHostedZone,
  ChangeTagsForResource,
  CreateKeySigningKey,
  CreateVPCAssociationAuthorization,
  TestDNSAnswer,
  UpdateHostedZoneComment,
} from "@mws-dashboard/ui/model/route53";
import type { Metadata } from "next";
import Link from "next/link";

import { aliasKind } from "../../../lib/aliases";
import { recordChoices, recordDefaults, recordName, routingSummary } from "../../../lib/choices";
import { ICONS, ec2, healthHref, kmsUsEast1, logsUsEast1, nameTag, route53 } from "../../../lib/clients";
import { RecordFields, type RecordChoices } from "../../../lib/record-fields";
import {
  addTag,
  associateVpc,
  authorizeVpc,
  createKsk,
  createQueryLogging,
  deleteQueryLogging,
  deleteRecord,
  deleteZone,
  disassociateVpc,
  kskAction,
  removeTag,
  revokeVpc,
  saveRecord,
  setSigning,
  testAnswer,
  updateComment,
} from "../actions";

export const metadata: Metadata = { title: "Hosted zone" };

type Props = { searchParams: Promise<{ id?: string; tab?: string; name?: string; type?: string; ident?: string }> };

const PAGE = 300;
const TAG = ChangeTagsForResource.AddTags.item!.fields!;
const TEST_TYPES = TestDNSAnswer.RecordType.enum ?? ["A"];

/** What a record does, so the zone reads by purpose: where traffic goes,
 * where mail goes, and the zone's own plumbing. */
function purpose(r: ResourceRecordSet) {
  if (r.Type === "NS" || r.Type === "SOA" || r.Type === "DS") return "zone";
  if (r.Type === "MX" || (r.Type === "TXT" && r.ResourceRecords?.some((v) => /v=spf1|v=DKIM1|v=DMARC1/i.test(v.Value ?? ""))) || /(_domainkey|_dmarc)\./.test(r.Name ?? "")) return "mail";
  if (r.Type === "CNAME" && /^_[0-9a-f]{32}\./.test(r.Name ?? "")) return "validation";
  if (r.Type === "TXT") return "verification";
  return "traffic";
}

function RecordForm({ zone, record, domain, names, choices }: { zone: string; record?: ResourceRecordSet; domain: string; names: string[]; choices: RecordChoices }) {
  const testId = record ? `edit-record-${record.Name}-${record.Type}${record.SetIdentifier ? `-${record.SetIdentifier}` : ""}` : "create-record";
  return (
    <ActionForm action={saveRecord.bind(null, zone, record ?? null)} submit={record ? "Save record" : "Create record"} testId={testId}>
      <RecordFields zone={domain} zoneId={zone} names={names} defaults={recordDefaults(record, domain)} choices={choices} />
    </ActionForm>
  );
}

async function Records({ id, domain, start }: { id: string; domain: string; start: { name?: string; type?: string; ident?: string } }) {
  const data = await load(async () => {
    const r = await (await route53()).send(
      new ListResourceRecordSetsCommand({
        HostedZoneId: id,
        MaxItems: PAGE,
        StartRecordName: start.name,
        StartRecordType: start.type as RRType | undefined,
        StartRecordIdentifier: start.ident,
      }),
    );
    return r;
  });
  if (!data.ok) return <ErrorNotice error={data.error} />;
  const records = data.value.ResourceRecordSets ?? [];
  const names = [...new Set(records.filter((r) => !r.AliasTarget && r.Type !== "NS" && r.Type !== "SOA").map((r) => recordName(r.Name)))];
  const choices = await recordChoices(id, names);
  const checkLabel = new Map(choices.healthChecks.map((h) => [h.id, h.label]));
  const geoLabel = new Map(choices.geos.map((g) => [g.value, g.label]));
  const next = data.value.IsTruncated
    ? `/route53/zone?${new URLSearchParams({
        id,
        name: data.value.NextRecordName ?? "",
        type: data.value.NextRecordType ?? "",
        ...(data.value.NextRecordIdentifier ? { ident: data.value.NextRecordIdentifier } : {}),
      })}`
    : undefined;
  const sections = [
    { id: "traffic", title: "Traffic", items: records.filter((r) => purpose(r) === "traffic") },
    { id: "mail", title: "Mail", items: records.filter((r) => purpose(r) === "mail") },
    { id: "verification", title: "Verification", items: records.filter((r) => purpose(r) === "verification" || purpose(r) === "validation") },
    { id: "zone", title: "Zone", items: records.filter((r) => purpose(r) === "zone") },
  ];
  return (
    <Section
      plain
      actions={
        <Sheet title="Create record" label="Create record" icon={<Plus size={16} />} testId="create-record">
          <RecordForm zone={id} domain={domain} names={names} choices={choices} />
        </Sheet>
      }
    >
      <Curated
        label="Records"
        sections={sections}
        empty={<Empty icon={ICONS.zone} />}
        row={(r) => {
          const name = recordName(r.Name);
          const value = r.AliasTarget ? r.AliasTarget.DNSName?.replace(/\.$/, "") : r.ResourceRecords?.map((v) => v.Value).join(", ");
          const locked = (r.Type === "NS" || r.Type === "SOA") && name === domain && !r.SetIdentifier;
          const kind = r.AliasTarget ? aliasKind(r.AliasTarget.HostedZoneId, r.AliasTarget.DNSName, id) : null;
          const routing = routingSummary(r, geoLabel);
          const label = `${name} ${r.Type}${r.SetIdentifier ? ` ${r.SetIdentifier}` : ""}`;
          return {
            key: `${r.Name}-${r.Type}-${r.SetIdentifier ?? ""}`,
            icon: <Pill tone={r.AliasTarget ? "info" : "neutral"}>{r.Type}</Pill>,
            title: name === domain ? <span>{name}</span> : <span>{name.slice(0, -domain.length - 1)}<span className="muted">.{domain}</span></span>,
            subtitle: kind?.href ? (
              <Link href={kind.href}>
                <code className="clip">{value}</code>
              </Link>
            ) : (
              <code className="clip">{value}</code>
            ),
            meta: (
              <>
                {kind && <Pill tone="info">{kind.label}</Pill>}
                {r.AliasTarget?.EvaluateTargetHealth && <HeartPulse size={14} aria-label="Evaluates target health" />}
                {r.SetIdentifier && <Pill title={r.SetIdentifier}>{routing ?? r.SetIdentifier}</Pill>}
                {r.HealthCheckId && (
                  <Link href={healthHref(r.HealthCheckId)} title={checkLabel.get(r.HealthCheckId) ?? r.HealthCheckId}>
                    <HeartPulse size={14} aria-label="Health check" />
                  </Link>
                )}
                {r.TTL !== undefined && <span title="TTL">{r.TTL}s</span>}
              </>
            ),
            actions: locked ? undefined : (
              <>
                <Sheet title="Edit record" label={`Edit ${label}`} icon={<Pencil size={15} />} testId={`edit-record-${r.Name}-${r.Type}${r.SetIdentifier ? `-${r.SetIdentifier}` : ""}`}>
                  <RecordForm zone={id} record={r} domain={domain} names={names} choices={choices} />
                </Sheet>
                <ActionForm action={deleteRecord.bind(null, id, r)} submit={`Delete ${label}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${label}?`} />
              </>
            ),
          };
        }}
      />
      <More shown={records.length} href={next} noun="records" />
    </Section>
  );
}

async function Vpcs({ id, vpcs }: { id: string; vpcs: { VPCId?: string; VPCRegion?: string }[] }) {
  const current = await region();
  const [mine, auths] = await Promise.all([
    load(async () => (await (await ec2()).send(new DescribeVpcsCommand({}))).Vpcs ?? []),
    load(async () => (await (await route53()).send(new ListVPCAssociationAuthorizationsCommand({ HostedZoneId: id }))).VPCs ?? []),
  ]);
  const free = mine.ok ? mine.value.filter((v) => !vpcs.some((a) => a.VPCId === v.VpcId)) : [];
  const regions = AssociateVPCWithHostedZone.VPC.fields!.VPCRegion.enum ?? [];
  return (
    <>
      <Section
        title="VPCs"
        count={vpcs.length}
        plain
        actions={
          <Sheet title="Associate VPC" label="Associate VPC" testId="associate-vpc">
            <ActionForm action={associateVpc.bind(null, id)} submit="Associate" testId="associate-vpc">
              <Field label="VPC" member="VPC.VPCId">
                <select name="vpc" required>
                  {free.map((v) => (
                    <option key={v.VpcId} value={v.VpcId}>
                      {nameTag(v) ?? v.VpcId} · {v.CidrBlock}
                    </option>
                  ))}
                </select>
              </Field>
              <input type="hidden" name="region" value={current} />
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Associated VPCs"
          rows={vpcs.map((v) => ({
            key: `${v.VPCId}-${v.VPCRegion}`,
            icon: <AwsIcon icon={ICONS.vpc} size={22} />,
            title: v.VPCId,
            subtitle: v.VPCRegion,
            href: v.VPCRegion === current ? `/vpc/${v.VPCId}` : undefined,
            actions:
              vpcs.length > 1 ? (
                <ActionForm action={disassociateVpc.bind(null, id, v.VPCId!, v.VPCRegion!)} submit={`Disassociate ${v.VPCId}`} icon={<X size={15} />} tone="danger" confirm={`Disassociate ${v.VPCId}?`} />
              ) : undefined,
          }))}
        />
      </Section>
      <Section
        title="Authorizations for other accounts"
        count={auths.ok ? auths.value.length : undefined}
        plain
        actions={
          <Sheet title="Authorize VPC association" label="Authorize another account's VPC" testId="authorize-vpc">
            <ActionForm action={authorizeVpc.bind(null, id)} submit="Authorize" testId="authorize-vpc">
              <div className="form-row">
                <Field label="VPC ID" rule={{ ...CreateVPCAssociationAuthorization.VPC.fields!.VPCId, required: true, pattern: "^vpc-[0-9a-f]{8,17}$", hint: "Like vpc-0abc12345" }} member="VPC.VPCId">
                  <input name="vpc" />
                </Field>
                <Field label="Region" member="VPC.VPCRegion">
                  <select name="region" defaultValue={current}>
                    {regions.map((r) => (
                      <option key={r}>{r}</option>
                    ))}
                  </select>
                </Field>
              </div>
            </ActionForm>
          </Sheet>
        }
      >
        {auths.ok ? (
          <List
            label="Authorizations"
            rows={auths.value.map((v) => ({
              key: `${v.VPCId}-${v.VPCRegion}`,
              icon: <AwsIcon icon={ICONS.vpc} size={22} />,
              title: v.VPCId,
              subtitle: v.VPCRegion,
              actions: <ActionForm action={revokeVpc.bind(null, id, v.VPCId!, v.VPCRegion!)} submit={`Revoke ${v.VPCId}`} icon={<X size={15} />} tone="danger" />,
            }))}
          />
        ) : (
          <ErrorNotice error={auths.error} />
        )}
      </Section>
    </>
  );
}

/** KMS keys Route 53 can sign with (ECC_NIST_P256 signing keys in us-east-1). */
async function signingKeys() {
  const kms = await kmsUsEast1();
  const keys = (await kms.send(new ListKeysCommand({ Limit: 100 }))).Keys ?? [];
  const described = await Promise.all(keys.slice(0, 100).map((k) => kms.send(new DescribeKeyCommand({ KeyId: k.KeyId })).then((r) => r.KeyMetadata, () => undefined)));
  return described
    .filter((m) => m && m.KeySpec === "ECC_NIST_P256" && m.KeyUsage === "SIGN_VERIFY" && m.KeyState === "Enabled" && m.KeyManager === "CUSTOMER")
    .map((m) => ({ value: m!.Arn!, label: m!.Description || m!.KeyId! }));
}

async function Dnssec({ id, domain }: { id: string; domain: string }) {
  const [dnssec, keys] = await Promise.all([load(async () => (await route53()).send(new GetDNSSECCommand({ HostedZoneId: id }))), signingKeys().catch(() => [])]);
  if (!dnssec.ok) return <ErrorNotice error={dnssec.error} />;
  const { Status: status, KeySigningKeys: ksks = [] } = dnssec.value;
  const signing = status?.ServeSignature === "SIGNING";
  const active = ksks.some((k) => k.Status === "ACTIVE");
  return (
    <>
      <Specs
        items={[
          { label: "Signing", icon: <ShieldCheck size={15} />, value: <Status tone={signing ? "good" : "neutral"}>{status?.ServeSignature?.toLowerCase().replace(/_/g, " ")}</Status> },
          status?.StatusMessage && { label: "Status message", icon: <ShieldCheck size={15} />, value: status.StatusMessage },
        ]}
      />
      <Section
        title="Key-signing keys"
        count={ksks.length}
        plain
        actions={
          <>
            <Sheet title="Create key-signing key" label="Create key-signing key" testId="create-ksk">
              <ActionForm action={createKsk.bind(null, id)} submit="Create" testId="create-ksk">
                <Field label="Name" rule={{ ...CreateKeySigningKey.Name, pattern: "^[A-Za-z0-9_]+$", hint: "Letters, digits and underscores" }} generate="name" unique>
                  <input name="name" required defaultValue={`${domain.split(".")[0].replace(/[^A-Za-z0-9_]/g, "_")}_ksk`.slice(0, 128)} />
                </Field>
                <AutoPick name="kms" label="KMS key (us-east-1)" options={keys} creates={`ECC_NIST_P256 key for ${domain}`} testId="ksk-kms" />
              </ActionForm>
            </Sheet>
            {signing ? (
              <ActionForm action={setSigning.bind(null, id, false)} submit="Disable DNSSEC signing" icon={<Pause size={16} />} confirm="Disable signing? Remove the DS record from the parent first." testId="disable-dnssec" />
            ) : (
              active && <ActionForm action={setSigning.bind(null, id, true)} submit="Enable DNSSEC signing" icon={<Play size={16} />} testId="enable-dnssec" />
            )}
          </>
        }
      >
        <List
          label="Key-signing keys"
          empty={<Empty icon={ICONS.zone} />}
          rows={ksks.map((k) => ({
            key: k.Name!,
            icon: <KeyRound size={18} />,
            title: k.Name,
            subtitle: k.DSRecord ? <code className="clip">DS {k.DSRecord}</code> : k.KmsArn,
            meta: (
              <>
                {k.KeyTag !== undefined && <span title="Key tag">{k.KeyTag}</span>}
                <Status tone={k.Status === "ACTIVE" ? "good" : k.Status === "INACTIVE" ? "neutral" : "warn"}>{k.Status?.toLowerCase()}</Status>
              </>
            ),
            actions: (
              <>
                {k.Status === "ACTIVE" ? (
                  <ActionForm action={kskAction.bind(null, id, k.Name!, "deactivate")} submit={`Deactivate ${k.Name}`} icon={<Pause size={15} />} />
                ) : (
                  <>
                    <ActionForm action={kskAction.bind(null, id, k.Name!, "activate")} submit={`Activate ${k.Name}`} icon={<Play size={15} />} />
                    <ActionForm action={kskAction.bind(null, id, k.Name!, "delete")} submit={`Delete ${k.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${k.Name}?`} />
                  </>
                )}
              </>
            ),
          }))}
        />
      </Section>
      {ksks
        .filter((k) => k.Status === "ACTIVE" && k.DSRecord)
        .map((k) => (
          <Section key={k.Name} title={`DS record for the parent zone · ${k.Name}`} plain>
            <CodeBlock value={`${domain}. 3600 IN DS ${k.DSRecord}`} label="DS record" />
          </Section>
        ))}
    </>
  );
}

async function QueryLogging({ id, domain }: { id: string; domain: string }) {
  const [configs, groups] = await Promise.all([
    load(async () => (await (await route53()).send(new ListQueryLoggingConfigsCommand({ HostedZoneId: id }))).QueryLoggingConfigs ?? []),
    (async () => ((await (await logsUsEast1()).send(new DescribeLogGroupsCommand({ logGroupNamePrefix: "/aws/route53/" }))).logGroups ?? []).map((g) => ({ value: g.arn!.replace(/:\*$/, ""), label: g.logGroupName! })))().catch(() => []),
  ]);
  if (!configs.ok) return <ErrorNotice error={configs.error} />;
  const name = `/aws/route53/${domain}`;
  return (
    <Section
      title="Query logging"
      plain
      actions={
        configs.value.length === 0 && (
          <Sheet title="Configure query logging" label="Configure query logging" testId="create-query-logging">
            <ActionForm action={createQueryLogging.bind(null, id, domain)} submit="Create" testId="create-query-logging">
              <AutoPick name="group" label="Log group (us-east-1)" options={groups} creates={name} preferred={groups.find((g) => g.label === name)?.value} testId="query-log-group" />
            </ActionForm>
          </Sheet>
        )
      }
    >
      <List
        label="Query logging configurations"
        empty={<Empty icon={ICONS.route53} />}
        rows={configs.value.map((c) => {
          const group = c.CloudWatchLogsLogGroupArn?.split(":log-group:")[1];
          return {
            key: c.Id!,
            icon: <ScrollText size={18} />,
            title: group,
            subtitle: "us-east-1",
            href: group ? `/logs/group?name=${encodeURIComponent(group)}` : undefined,
            actions: <ActionForm action={deleteQueryLogging.bind(null, c.Id!)} submit="Delete query logging" icon={<Trash2 size={15} />} tone="danger" confirm="Stop logging queries?" />,
          };
        })}
      />
    </Section>
  );
}

async function ZoneTags({ id }: { id: string }) {
  const tags = await load(async () => (await (await route53()).send(new ListTagsForResourceCommand({ ResourceType: "hostedzone", ResourceId: id }))).ResourceTagSet?.Tags ?? []);
  if (!tags.ok) return <ErrorNotice error={tags.error} />;
  return (
    <Section
      title="Tags"
      count={tags.value.length}
      plain
      actions={
        <Sheet title="Add tag" label="Add tag" testId="add-zone-tag">
          <ActionForm action={addTag.bind(null, "hostedzone", id)} submit="Add tag" testId="add-zone-tag">
            <div className="form-row">
              <Field label="Key" rule={TAG.Key}>
                <input name="key" required />
              </Field>
              <Field label="Value" rule={TAG.Value}>
                <input name="value" />
              </Field>
            </div>
          </ActionForm>
        </Sheet>
      }
    >
      <List
        label="Tags"
        empty={<Empty icon={ICONS.zone} />}
        rows={tags.value.map((t) => ({
          key: t.Key!,
          icon: <Tag size={16} />,
          title: t.Key,
          subtitle: t.Value,
          actions: <ActionForm action={removeTag.bind(null, "hostedzone", id, t.Key!)} submit={`Remove tag ${t.Key}`} icon={<X size={15} />} tone="danger" />,
        }))}
      />
    </Section>
  );
}

export default async function HostedZone({ searchParams }: Props) {
  const { id = "", tab = "records", name, type, ident } = await searchParams;
  const back = { href: "/route53", label: "Hosted zones" };
  const data = await load(async () => (await route53()).send(new GetHostedZoneCommand({ Id: id })));
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.zone} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const zone = data.value;
  const domain = zone.HostedZone!.Name!.replace(/\.$/, "");
  const priv = !!zone.HostedZone?.Config?.PrivateZone;
  const href = (t: string) => `/route53/zone?id=${encodeURIComponent(id)}${t === "records" ? "" : `&tab=${t}`}`;
  const tabs = [
    { label: "Records", href: href("records"), active: tab === "records", count: zone.HostedZone?.ResourceRecordSetCount },
    priv && { label: "VPCs", href: href("vpcs"), active: tab === "vpcs", count: zone.VPCs?.length },
    !priv && { label: "DNSSEC signing", href: href("dnssec"), active: tab === "dnssec" },
    !priv && { label: "Query logging", href: href("logging"), active: tab === "logging" },
    { label: "Tags", href: href("tags"), active: tab === "tags" },
  ].filter((t): t is { label: string; href: string; active: boolean; count?: number } => !!t);
  return (
    <Page
      title={domain}
      icon={ICONS.zone}
      back={back}
      subtitle={id}
      actions={
        <>
          <Sheet title="Test record" label="Test record" icon={<FlaskConical size={16} />} testId="test-record">
            <ActionForm action={testAnswer.bind(null, id)} submit="Test" testId="test-record">
              <div className="form-row">
                <Field label="Record name" rule={TestDNSAnswer.RecordName} member="RecordName">
                  <input name="name" defaultValue={domain} required />
                </Field>
                <Field label="Type" rule={TestDNSAnswer.RecordType} member="RecordType">
                  <select name="type" defaultValue="A">
                    {TEST_TYPES.map((t) => (
                      <option key={t}>{t}</option>
                    ))}
                  </select>
                </Field>
              </div>
              <div className="form-row">
                <Field label="Resolver IP" rule={TestDNSAnswer.ResolverIP} format="ipv4" member="ResolverIP">
                  <input name="resolver" placeholder="192.0.2.53" />
                </Field>
                <Field label="Client subnet (EDNS0)" rule={TestDNSAnswer.EDNS0ClientSubnetIP} member="EDNS0ClientSubnetIP">
                  <input name="subnet" placeholder="198.51.100.0" />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
          <Sheet title="Edit description" label="Edit description" icon={<Pencil size={16} />} testId="edit-zone-comment">
            <ActionForm action={updateComment.bind(null, id)} submit="Save" testId="edit-zone-comment">
              <Field label="Description" rule={UpdateHostedZoneComment.Comment} member="Comment">
                <input name="comment" defaultValue={zone.HostedZone?.Config?.Comment} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteZone.bind(null, id)} submit="Delete hosted zone" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${domain}?`} testId="delete-zone" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Type", icon: priv ? <Lock size={15} /> : <AwsIcon icon={ICONS.internet} size={16} />, value: priv ? "Private" : "Public" },
          { label: "Records", icon: <Hash size={15} />, value: zone.HostedZone?.ResourceRecordSetCount },
          zone.HostedZone?.Config?.Comment && { label: "Description", icon: <Pencil size={15} />, value: zone.HostedZone.Config.Comment },
          zone.DelegationSet?.NameServers?.length && { label: "Name servers", icon: <Server size={15} />, value: zone.DelegationSet.NameServers.join(" ") },
        ]}
      />
      <Segments label="Hosted zone" items={tabs} />
      {tab === "records" && <Records id={id} domain={domain} start={{ name, type, ident }} />}
      {tab === "vpcs" && priv && <Vpcs id={id} vpcs={zone.VPCs ?? []} />}
      {tab === "dnssec" && !priv && <Dnssec id={id} domain={domain} />}
      {tab === "logging" && !priv && <QueryLogging id={id} domain={domain} />}
      {tab === "tags" && <ZoneTags id={id} />}
    </Page>
  );
}
