import {
  GetHealthCheckCommand,
  GetHealthCheckLastFailureReasonCommand,
  GetHealthCheckStatusCommand,
  ListTagsForResourceCommand,
} from "@aws-sdk/client-route-53";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status, Table } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { AlertTriangle, Clock, HeartPulse, Pencil, Repeat, Tag, Trash2, X } from "lucide-react";
import { ChangeTagsForResource, UpdateHealthCheck } from "@mws-dashboard/ui/model/route53";
import type { Metadata } from "next";

import { allHealthChecks, healthCheckNames, healthCheckTarget, recordName, recordsUsing, routingSummary } from "../../../lib/choices";
import { ICONS, healthHref, route53, zoneHref } from "../../../lib/clients";
import { HealthFields } from "../../../lib/health-fields";
import { CHECKER_REGIONS, healthDefaults, healthOf } from "../../../lib/health";
import { addTag, deleteHealthCheck, removeTag, updateHealthCheck } from "../actions";

export const metadata: Metadata = { title: "Health check" };

type Props = { searchParams: Promise<{ id?: string }> };

const TAG = ChangeTagsForResource.AddTags.item!.fields!;

export default async function HealthCheck({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/route53?tab=health", label: "Health checks" };
  const data = await load(async () => {
    const client = await route53();
    const [check, status, failure, tags, using, everyone] = await Promise.all([
      client.send(new GetHealthCheckCommand({ HealthCheckId: id })).then((r) => r.HealthCheck!),
      client.send(new GetHealthCheckStatusCommand({ HealthCheckId: id })).then((r) => r.HealthCheckObservations ?? [], () => []),
      client.send(new GetHealthCheckLastFailureReasonCommand({ HealthCheckId: id })).then((r) => r.HealthCheckObservations ?? [], () => []),
      client.send(new ListTagsForResourceCommand({ ResourceType: "healthcheck", ResourceId: id })).then((r) => r.ResourceTagSet?.Tags ?? [], () => []),
      recordsUsing(id).catch(() => []),
      allHealthChecks().catch(() => []),
    ]);
    const names = await healthCheckNames(everyone.map((h) => h.Id!)).catch(() => ({}) as Record<string, string>);
    return { check, status, failure, tags, using, everyone, names };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.health} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { check, status, failure, tags, using, everyone, names } = data.value;
  const c = check.HealthCheckConfig!;
  const name = tags.find((t) => t.Key === "Name")?.Value;
  const health = healthOf(status);
  const target = healthCheckTarget(check);
  const others = everyone.filter((h) => h.Id !== id).map((h) => ({ id: h.Id!, label: names[h.Id!] ?? healthCheckTarget(h) }));
  const lastFailure = failure.filter((o) => o.StatusReport?.Status).sort((a, b) => (b.StatusReport?.CheckedTime?.getTime() ?? 0) - (a.StatusReport?.CheckedTime?.getTime() ?? 0))[0];
  return (
    <Page
      title={name ?? target}
      icon={ICONS.health}
      back={back}
      subtitle={id}
      actions={
        <>
          <Sheet title="Edit health check" label="Edit health check" icon={<Pencil size={16} />} testId="edit-health-check">
            <ActionForm action={updateHealthCheck.bind(null, id)} submit="Save" testId="edit-health-check">
              <HealthFields rules={UpdateHealthCheck} defaults={healthDefaults(check, name)} others={others} checkerRegions={CHECKER_REGIONS} editing />
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteHealthCheck.bind(null, id, true)} submit="Delete health check" icon={<Trash2 size={16} />} tone="danger" confirm="Delete this health check?" testId="delete-health-check" />
        </>
      }
    >
      <LiveRefresh every={10000} />
      <Specs
        items={[
          { label: "Status", icon: <HeartPulse size={15} />, value: <Status tone={health.tone}>{health.word}</Status> },
          health.total > 0 && { label: "Checkers reporting healthy", icon: <HeartPulse size={15} />, value: `${health.healthy}/${health.total}` },
          name && { label: "Target", icon: <AwsIcon icon={ICONS.internet} size={16} />, value: target },
          c.RequestInterval && { label: "Interval", icon: <Repeat size={15} />, value: `${c.RequestInterval}s × ${c.FailureThreshold}` },
          c.SearchString && { label: "Search string", icon: <Tag size={15} />, value: <code>{c.SearchString}</code> },
          c.Inverted && { label: "Inverted", icon: <Repeat size={15} />, value: "Inverted" },
          c.Disabled && { label: "Disabled", icon: <AlertTriangle size={15} />, value: "Disabled" },
        ]}
      />
      {lastFailure && health.tone !== "good" && (
        <div className="banner error" role="alert">
          <AlertTriangle size={15} aria-hidden /> {lastFailure.StatusReport?.Status} · {lastFailure.Region} · {ago(lastFailure.StatusReport?.CheckedTime)}
        </div>
      )}
      {c.Type === "CALCULATED" && (
        <Section title="Monitored health checks" count={c.ChildHealthChecks?.length ?? 0} plain>
          <List
            label="Monitored health checks"
            rows={(c.ChildHealthChecks ?? []).map((child) => ({
              key: child,
              icon: <HeartPulse size={18} />,
              title: names[child] ?? child,
              href: healthHref(child),
            }))}
          />
        </Section>
      )}
      {status.length > 0 && (
        <Section title="Health checkers" count={status.length} plain>
          <Table
            label="Health checkers"
            rowKey={(o) => `${o.Region}-${o.IPAddress}`}
            rows={status}
            columns={[
              { header: "Region", cell: (o) => o.Region },
              { header: "Checker IP", cell: (o) => <code>{o.IPAddress}</code> },
              { header: "Status", cell: (o) => <Status tone={o.StatusReport?.Status?.startsWith("Success") ? "good" : "bad"}>{o.StatusReport?.Status}</Status> },
              { header: <Clock size={14} aria-label="Checked" />, cell: (o) => ago(o.StatusReport?.CheckedTime) },
            ]}
          />
        </Section>
      )}
      <Section title="Records" count={using.length} plain>
        <List
          label="Records using this health check"
          empty={<Empty icon={ICONS.zone} />}
          rows={using.map(({ zone, record }) => ({
            key: `${zone.Id}-${record.Name}-${record.Type}-${record.SetIdentifier ?? ""}`,
            icon: <Pill>{record.Type}</Pill>,
            title: recordName(record.Name),
            subtitle: zone.Name?.replace(/\.$/, ""),
            href: zoneHref(zone.Id),
            meta: routingSummary(record) ? <Pill>{routingSummary(record)}</Pill> : undefined,
          }))}
        />
      </Section>
      <Section
        title="Tags"
        count={tags.length}
        plain
        actions={
          <Sheet title="Add tag" label="Add tag" testId="add-health-tag">
            <ActionForm action={addTag.bind(null, "healthcheck", id)} submit="Add tag" testId="add-health-tag">
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
          rows={tags.map((t) => ({
            key: t.Key!,
            icon: <Tag size={16} />,
            title: t.Key,
            subtitle: t.Value,
            actions: <ActionForm action={removeTag.bind(null, "healthcheck", id, t.Key!)} submit={`Remove tag ${t.Key}`} icon={<X size={15} />} tone="danger" />,
          }))}
        />
      </Section>
    </Page>
  );
}
