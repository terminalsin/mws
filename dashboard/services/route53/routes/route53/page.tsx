import { DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { GetHealthCheckStatusCommand, ListHostedZonesCommand, ListReusableDelegationSetsCommand } from "@aws-sdk/client-route-53";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { HeartPulse, Lock, Trash2 } from "lucide-react";
import { CreateHealthCheck } from "@mws-dashboard/ui/model/route53";
import type { Metadata } from "next";

import { allHealthChecks, healthCheckNames, healthCheckTarget } from "../../lib/choices";
import { ICONS, ec2, healthHref, nameTag, route53, zoneHref } from "../../lib/clients";
import { HealthFields } from "../../lib/health-fields";
import { ZoneFields } from "../../lib/zone-fields";
import { CHECKER_REGIONS, healthOf } from "../../lib/health";
import { createHealthCheck, createZone, deleteHealthCheck } from "./actions";

export const metadata: Metadata = { title: "Route 53" };

const CHECK = CreateHealthCheck.HealthCheckConfig.fields!;

type Props = { searchParams: Promise<{ tab?: string }> };

async function HealthChecks() {
  const checks = await load(async () => {
    const client = await route53();
    const list = await allHealthChecks();
    const [names, statuses] = await Promise.all([
      healthCheckNames(list.map((h) => h.Id!)),
      Promise.all(list.map((h) => client.send(new GetHealthCheckStatusCommand({ HealthCheckId: h.Id })).then((r) => r.HealthCheckObservations ?? [], () => []))),
    ]);
    return list.map((h, i) => ({ h, name: names[h.Id!], status: healthOf(statuses[i]) }));
  });
  if (!checks.ok) return <ErrorNotice error={checks.error} />;
  return (
    <>
      {/* Checkers report on the probe interval: keep the states current. */}
      {checks.value.length > 0 && <LiveRefresh every={10000} />}
      <List
        label="Health checks"
        empty={<Empty icon={ICONS.health} />}
        rows={checks.value.map(({ h, name, status }) => {
          const c = h.HealthCheckConfig!;
          const target = healthCheckTarget(h);
          return {
            key: h.Id!,
            icon: <HeartPulse size={20} className={status.tone === "good" ? "tone-good" : status.tone === "bad" ? "tone-bad" : "muted"} />,
            title: name ?? target,
            subtitle: name ? target : undefined,
            href: healthHref(h.Id),
            meta: (
              <>
                {c.Disabled && <Pill>Disabled</Pill>}
                {c.Inverted && <Pill>Inverted</Pill>}
                <Status tone={status.tone}>{status.word}</Status>
              </>
            ),
            actions: <ActionForm action={deleteHealthCheck.bind(null, h.Id!, false)} submit="Delete health check" icon={<Trash2 size={15} />} tone="danger" confirm="Delete this health check?" />,
          };
        })}
      />
    </>
  );
}

export default async function Route53({ searchParams }: Props) {
  const { tab = "zones" } = await searchParams;
  if (tab === "health") {
    const others = await load(allHealthChecks);
    const names = others.ok ? await healthCheckNames(others.value.map((h) => h.Id!)).catch(() => ({}) as Record<string, string>) : {};
    return (
      <Page
        title="Health checks"
        actions={
          <Sheet title="Create health check" label="Create health check" testId="create-health-check">
            <ActionForm action={createHealthCheck} submit="Create" testId="create-health-check">
              <HealthFields
                rules={CHECK}
                defaults={{ kind: "http" }}
                checkerRegions={CHECKER_REGIONS}
                others={(others.ok ? others.value : []).map((h) => ({ id: h.Id!, label: names[h.Id!] ?? healthCheckTarget(h) }))}
              />
            </ActionForm>
          </Sheet>
        }
      >
        <HealthChecks />
      </Page>
    );
  }
  const [zones, vpcs, sets] = await Promise.all([
    load(async () => {
      const client = await route53();
      return all(
        (Marker) => client.send(new ListHostedZonesCommand({ Marker })),
        (r) => r.HostedZones,
        (r) => (r.IsTruncated ? r.NextMarker : undefined),
      );
    }),
    load(async () => (await (await ec2()).send(new DescribeVpcsCommand({}))).Vpcs ?? []),
    load(async () => (await (await route53()).send(new ListReusableDelegationSetsCommand({}))).DelegationSets ?? []),
  ]);
  const create = (
    <Sheet title="Create hosted zone" label="Create hosted zone" testId="create-zone">
      <ActionForm action={createZone} submit="Create hosted zone" testId="create-zone">
        <ZoneFields
          vpcs={vpcs.ok ? vpcs.value.map((v) => ({ id: v.VpcId!, name: nameTag(v) ?? v.VpcId!, cidr: v.CidrBlock })) : []}
          sets={sets.ok ? sets.value.map((d) => ({ id: d.Id!.split("/").pop()!, label: `${d.NameServers?.[0] ?? d.Id} …` })) : []}
        />
      </ActionForm>
    </Sheet>
  );
  if (!zones.ok) {
    return (
      <Page title="Hosted zones" actions={create}>
        <ErrorNotice error={zones.error} />
      </Page>
    );
  }
  const list = zones.value.sort((a, b) => a.Name!.localeCompare(b.Name!));
  return (
    <Page title="Hosted zones" actions={create}>
      <Curated
        label="Hosted zones"
        sections={[
          { id: "public", title: "Public", items: list.filter((z) => !z.Config?.PrivateZone) },
          { id: "private", title: "Private", items: list.filter((z) => z.Config?.PrivateZone) },
        ]}
        empty={<Empty icon={ICONS.zone} action={create} />}
        row={(z) => ({
          key: z.Id!,
          icon: <AwsIcon icon={ICONS.zone} size={24} />,
          title: z.Name!.replace(/\.$/, ""),
          subtitle: z.Config?.Comment,
          href: zoneHref(z.Id),
          meta: (
            <>
              {z.Config?.PrivateZone && <Lock size={14} aria-label="Private" />}
              {z.LinkedService?.ServicePrincipal && <Pill>{z.LinkedService.ServicePrincipal.split(".")[0]}</Pill>}
              <Pill title="Records">{z.ResourceRecordSetCount}</Pill>
            </>
          ),
        })}
      />
    </Page>
  );
}
