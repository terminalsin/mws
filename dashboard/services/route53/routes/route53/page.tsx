import { DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { GetHealthCheckStatusCommand, ListHealthChecksCommand, ListHostedZonesCommand } from "@aws-sdk/client-route-53";
import { collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { HeartPulse, Lock, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ec2, nameTag, route53 } from "../../lib/clients";
import { createHealthCheck, createZone, deleteHealthCheck } from "./actions";

export const metadata: Metadata = { title: "Route 53" };

type Props = { searchParams: Promise<{ tab?: string }> };

async function HealthChecks() {
  const checks = await load(async () => {
    const client = await route53();
    const list = await collect(
      (Marker) => client.send(new ListHealthChecksCommand({ Marker })),
      (r) => r.HealthChecks,
      (r) => (r.IsTruncated ? r.NextMarker : undefined),
    );
    return Promise.all(
      list.map(async (h) => {
        const status = await client.send(new GetHealthCheckStatusCommand({ HealthCheckId: h.Id })).then(
          (r) => r.HealthCheckObservations ?? [],
          () => [],
        );
        const healthy = status.filter((o) => o.StatusReport?.Status?.startsWith("Success")).length;
        return { h, healthy, total: status.length };
      }),
    );
  });
  if (!checks.ok) return <ErrorNotice error={checks.error} />;
  return (
    <List
      label="Health checks"
      empty={<Empty icon={ICONS.route53} />}
      rows={checks.value.map(({ h, healthy, total }) => {
        const c = h.HealthCheckConfig!;
        const target = c.FullyQualifiedDomainName ?? c.IPAddress;
        const ok = total === 0 || healthy * 2 > total;
        return {
          key: h.Id!,
          icon: <HeartPulse size={20} className={ok ? "tone-good" : "tone-bad"} />,
          title: c.Type?.startsWith("HTTP") ? `${c.Type.toLowerCase().replace("_str_match", "")}://${target}${c.Port && c.Port !== 80 && c.Port !== 443 ? `:${c.Port}` : ""}${c.ResourcePath ?? ""}` : `${c.Type} ${target ?? ""}`,
          meta: (
            <>
              <Status tone={total === 0 ? "neutral" : ok ? "good" : "bad"}>{total === 0 ? "Unknown" : ok ? "Healthy" : "Unhealthy"}</Status>
              <span>{c.RequestInterval}s</span>
            </>
          ),
          actions: <ActionForm action={deleteHealthCheck.bind(null, h.Id!)} submit="Delete health check" icon={<Trash2 size={15} />} tone="danger" confirm="Delete this health check?" />,
        };
      })}
    />
  );
}

export default async function Route53({ searchParams }: Props) {
  const { tab = "zones" } = await searchParams;
  if (tab === "health") {
    return (
      <Page
        title="Health checks"
        actions={
          <Sheet title="Create health check" label="Create health check" testId="create-health-check">
            <ActionForm action={createHealthCheck} submit="Create" testId="create-health-check">
              <Field label="Endpoint URL">
                <input name="url" type="url" required placeholder="https://example.com/health" />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        <HealthChecks />
      </Page>
    );
  }
  const [zones, vpcs] = await Promise.all([
    load(async () => {
      const client = await route53();
      return collect(
        (Marker) => client.send(new ListHostedZonesCommand({ Marker })),
        (r) => r.HostedZones,
        (r) => (r.IsTruncated ? r.NextMarker : undefined),
      );
    }),
    load(async () => (await (await ec2()).send(new DescribeVpcsCommand({}))).Vpcs ?? []),
  ]);
  const create = (
    <Sheet title="Create hosted zone" label="Create hosted zone" testId="create-zone">
      <ActionForm action={createZone} submit="Create hosted zone" testId="create-zone">
        <Field label="Domain name">
          <input name="name" required placeholder="example.com" autoFocus />
        </Field>
        <Field label="Type">
          <select name="vpc" defaultValue="">
            <option value="">Public hosted zone</option>
            {vpcs.ok &&
              vpcs.value.map((v) => (
                <option key={v.VpcId} value={v.VpcId}>
                  Private · {nameTag(v) ?? v.VpcId}
                </option>
              ))}
          </select>
        </Field>
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
  const all = zones.value.sort((a, b) => a.Name!.localeCompare(b.Name!));
  return (
    <Page title="Hosted zones" actions={create}>
      <Curated
        label="Hosted zones"
        sections={[
          { id: "public", title: "Public", items: all.filter((z) => !z.Config?.PrivateZone) },
          { id: "private", title: "Private", items: all.filter((z) => z.Config?.PrivateZone) },
        ]}
        empty={<Empty icon={ICONS.zone} action={create} />}
        row={(z) => ({
          key: z.Id!,
          icon: <AwsIcon icon={ICONS.zone} size={24} />,
          title: z.Name!.replace(/\.$/, ""),
          subtitle: z.Config?.Comment,
          href: `/route53/zone?id=${encodeURIComponent(z.Id!.split("/").pop()!)}`,
          meta: (
            <>
              {z.Config?.PrivateZone && <Lock size={14} aria-label="Private" />}
              {z.LinkedService?.ServicePrincipal && <Pill>{z.LinkedService.ServicePrincipal.split(".")[0]}</Pill>}
              <span>{z.ResourceRecordSetCount} records</span>
            </>
          ),
        })}
      />
    </Page>
  );
}
