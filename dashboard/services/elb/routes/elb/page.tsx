import { DescribeLoadBalancersCommand as DescribeClassicCommand } from "@aws-sdk/client-elastic-load-balancing";
import { DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { DescribeTrustStoreAssociationsCommand, DescribeTrustStoresCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Page, Pill, Segments, Sheet, Status } from "@mws-dashboard/ui";
import { RefreshCw, Trash2 } from "lucide-react";
import { CreateTrustStore } from "@mws-dashboard/ui/model/elbv2";
import type { Metadata } from "next";

import { ICONS, LB_ICON, TARGET_ICON, classic, ec2, elb, nameTag } from "../../lib/clients";
import { healthCounts, lbHref, listLoadBalancers, listTargetGroups, tgHref } from "../../lib/elb";
import { LoadBalancerFields, TargetGroupFields, type VpcChoice } from "../../lib/create-forms";
import { LB_NAME } from "../../lib/rules";
import { createLoadBalancer, createTargetGroup, createTrustStore, deleteTrustStore, modifyTrustStore } from "./actions";
import { createClassic } from "./classic-actions";

export const metadata: Metadata = { title: "Load balancers" };

type Props = { searchParams: Promise<{ tab?: string }> };

const TABS = [
  { id: "lbs", label: "Load balancers" },
  { id: "targets", label: "Target groups" },
  { id: "truststores", label: "Trust stores" },
  { id: "classic", label: "Classic" },
];

function Tabs({ tab }: { tab: string }) {
  return <Segments label="Load balancing" items={TABS.map((t) => ({ label: t.label, href: t.id === "lbs" ? "/elb" : `/elb?tab=${t.id}`, active: tab === t.id }))} />;
}

const TRUST_NAME = { ...CreateTrustStore.Name, maxLength: 32, pattern: "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?$", hint: "Letters, digits and inner hyphens", generate: "name" as const };

function BundleFields() {
  return (
    <>
      <Field label="CA certificates (PEM)" format="certificates" member="CaCertificatesBundleS3Key">
        <textarea name="bundle" rows={5} placeholder="-----BEGIN CERTIFICATE-----" />
      </Field>
      <Field label="Or a bundle in S3" format="s3url" member="CaCertificatesBundleS3Bucket">
        <input name="s3" placeholder="s3://bucket/ca-bundle.pem" />
      </Field>
    </>
  );
}

async function TrustStores() {
  const stores = await load(async () => {
    const client = await elb();
    const list = await all(
      (Marker) => client.send(new DescribeTrustStoresCommand({ Marker })),
      (r) => r.TrustStores,
      (r) => r.NextMarker,
    );
    const used = await Promise.all(list.map((s) => client.send(new DescribeTrustStoreAssociationsCommand({ TrustStoreArn: s.TrustStoreArn })).then((r) => r.TrustStoreAssociations?.length ?? 0, () => 0)));
    return list.map((s, i) => ({ s, used: used[i] }));
  });
  const create = (
    <Sheet title="Create trust store" label="Create trust store" testId="create-trust-store">
      <ActionForm action={createTrustStore} submit="Create trust store" testId="create-trust-store">
        <Field label="Name" rule={TRUST_NAME} unique>
          <input name="name" required autoFocus />
        </Field>
        <BundleFields />
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Trust stores" actions={create}>
      <Tabs tab="truststores" />
      {stores.ok ? (
        <List
          label="Trust stores"
          empty={<Empty icon={ICONS.trust} action={create} />}
          rows={stores.value.map(({ s, used }) => ({
            key: s.TrustStoreArn!,
            icon: <AwsIcon icon={ICONS.trust} size={22} />,
            title: s.Name,
            subtitle: `${s.NumberOfCaCertificates ?? 0} CA certificates${s.TotalRevokedEntries ? ` · ${s.TotalRevokedEntries} revoked` : ""}`,
            meta: (
              <>
                {used > 0 && <Pill>{used} listeners</Pill>}
                <Status tone={s.Status === "ACTIVE" ? "good" : "warn"}>{s.Status?.toLowerCase()}</Status>
              </>
            ),
            actions: (
              <>
                <Sheet title={`Replace CA bundle of ${s.Name}`} label={`Replace CA bundle of ${s.Name}`} icon={<RefreshCw size={15} />}>
                  <ActionForm action={modifyTrustStore.bind(null, s.TrustStoreArn!)} submit="Replace">
                    <input type="hidden" name="name" value={s.Name} />
                    <BundleFields />
                  </ActionForm>
                </Sheet>
                <ActionForm action={deleteTrustStore.bind(null, s.TrustStoreArn!)} submit={`Delete ${s.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.Name}?`} />
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={stores.error} />
      )}
    </Page>
  );
}

async function ClassicList({ vpcOptions, defaultVpc }: { vpcOptions: React.ReactNode; defaultVpc?: string }) {
  const lbs = await load(async () => {
    const client = await classic();
    return all(
      (Marker) => client.send(new DescribeClassicCommand({ Marker })),
      (r) => r.LoadBalancerDescriptions,
      (r) => r.NextMarker,
    );
  });
  const create = (
    <Sheet title="Create Classic Load Balancer" label="Create Classic Load Balancer" testId="create-classic">
      <ActionForm action={createClassic} submit="Create" testId="create-classic">
        <Field label="Name" rule={LB_NAME} taken={lbs.ok ? lbs.value.map((l) => l.LoadBalancerName!) : undefined} unique>
          <input name="name" required maxLength={32} autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Scheme">
            <select name="scheme" defaultValue="internet-facing">
              <option value="internet-facing">Internet-facing</option>
              <option value="internal">Internal</option>
            </select>
          </Field>
          <Field label="VPC" member="Subnets">
            <select name="vpc" required defaultValue={defaultVpc}>
              {vpcOptions}
            </select>
          </Field>
        </div>
        <Field label="Listeners" rule={{ required: true, pattern: "^\\s*((HTTPS?|TCP|SSL):)?\\d{1,5}(\\s*(->|→|=>)\\s*((HTTPS?|TCP|SSL):)?\\d{1,5})?(\\s*[,\\n]\\s*((HTTPS?|TCP|SSL):)?\\d{1,5}(\\s*(->|→|=>)\\s*((HTTPS?|TCP|SSL):)?\\d{1,5})?)*\\s*$", hint: "Like HTTP:80 → HTTP:80" }}>
          <textarea name="listeners" rows={2} defaultValue="HTTP:80 → HTTP:80" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Classic Load Balancers" actions={create}>
      <Tabs tab="classic" />
      {lbs.ok ? (
        <List
          label="Classic Load Balancers"
          empty={<Empty icon={ICONS.classic} action={create} />}
          rows={lbs.value.map((l) => ({
            key: l.LoadBalancerName!,
            icon: <AwsIcon icon={ICONS.classic} size={24} />,
            title: l.LoadBalancerName,
            subtitle: <code className="clip">{l.DNSName}</code>,
            href: `/elb/classic?name=${encodeURIComponent(l.LoadBalancerName!)}`,
            meta: (
              <>
                {l.Scheme === "internal" && <Pill>internal</Pill>}
                <Pill icon={<AwsIcon icon={ICONS.instance} size={14} />} title="Instances">{l.Instances?.length ?? 0}</Pill>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={lbs.error} />
      )}
    </Page>
  );
}

export default async function LoadBalancers({ searchParams }: Props) {
  const { tab = "lbs" } = await searchParams;
  if (tab === "truststores") return <TrustStores />;
  const vpcs = await load(async () => (await (await ec2()).send(new DescribeVpcsCommand({}))).Vpcs ?? []);
  const vpcChoices: VpcChoice[] = vpcs.ok ? vpcs.value.map((v) => ({ id: v.VpcId!, label: `${nameTag(v) ?? v.VpcId} · ${v.CidrBlock}`, isDefault: v.IsDefault })) : [];
  const defaultVpc = vpcChoices.find((v) => v.isDefault)?.id;
  const vpcOptions = vpcs.ok
    ? vpcs.value.map((v) => (
        <option key={v.VpcId} value={v.VpcId}>
          {nameTag(v) ?? v.VpcId} · {v.CidrBlock}
        </option>
      ))
    : null;
  if (tab === "classic") return <ClassicList vpcOptions={vpcOptions} defaultVpc={defaultVpc} />;

  if (tab === "targets") {
    const groups = await load(listTargetGroups);
    const names = groups.ok ? groups.value.map((g) => g.group.TargetGroupName!) : [];
    const create = (
      <Sheet title="Create target group" label="Create target group" testId="create-target-group">
        <ActionForm action={createTargetGroup} submit="Create target group" testId="create-target-group">
          <TargetGroupFields names={names} vpcs={vpcChoices} />
        </ActionForm>
      </Sheet>
    );
    return (
      <Page title="Target groups" actions={create}>
        <Tabs tab="targets" />
        {groups.ok ? (
          <List
            label="Target groups"
            empty={<Empty icon={ICONS.elb} action={create} />}
            rows={groups.value.map(({ group: g, targets }) => {
              const { healthy, total } = healthCounts(targets);
              return {
                key: g.TargetGroupArn!,
                icon: <AwsIcon icon={TARGET_ICON[g.TargetType ?? "instance"] ?? ICONS.elb} size={24} />,
                title: g.TargetGroupName,
                subtitle: g.Protocol ? `${g.Protocol}:${g.Port}` : undefined,
                href: tgHref(g.TargetGroupArn),
                meta: (
                  <>
                    {g.LoadBalancerArns?.length === 0 && <Pill>Unused</Pill>}
                    <Status tone={total === 0 ? "neutral" : healthy === total ? "good" : healthy === 0 ? "bad" : "warn"}>
                      {healthy}/{total} healthy
                    </Status>
                  </>
                ),
              };
            })}
          />
        ) : (
          <ErrorNotice error={groups.error} />
        )}
      </Page>
    );
  }

  const lbs = await load(listLoadBalancers);
  const names = lbs.ok ? lbs.value.map((l) => l.LoadBalancerName!) : [];
  const create = (
    <Sheet title="Create load balancer" label="Create load balancer" testId="create-load-balancer">
      <ActionForm action={createLoadBalancer} submit="Create load balancer" testId="create-load-balancer">
        <LoadBalancerFields names={names} vpcs={vpcChoices} />
      </ActionForm>
    </Sheet>
  );
  if (!lbs.ok) {
    return (
      <Page title="Load balancers" actions={create}>
        <Tabs tab="lbs" />
        <ErrorNotice error={lbs.error} />
      </Page>
    );
  }
  return (
    <Page title="Load balancers" actions={create}>
      <Tabs tab="lbs" />
      <Curated
        label="Load balancers"
        sections={[
          { id: "internet", title: "Internet-facing", items: lbs.value.filter((l) => l.Scheme === "internet-facing") },
          { id: "internal", title: "Internal", items: lbs.value.filter((l) => l.Scheme !== "internet-facing") },
        ]}
        empty={<Empty icon={ICONS.alb} action={create} />}
        row={(l) => ({
          key: l.LoadBalancerArn!,
          icon: <AwsIcon icon={LB_ICON[l.Type ?? "application"] ?? ICONS.alb} size={24} />,
          title: l.LoadBalancerName,
          subtitle: <code className="clip">{l.DNSName}</code>,
          href: lbHref(l.LoadBalancerArn),
          meta: (
            <>
              {l.Scheme === "internal" && <Pill>internal</Pill>}
              <Status tone={l.State?.Code === "active" ? "good" : l.State?.Code === "failed" ? "bad" : "warn"}>{l.State?.Code}</Status>
            </>
          ),
        })}
      />
    </Page>
  );
}
