import { DescribeAssociationCommand, DescribeAssociationExecutionTargetsCommand, DescribeAssociationExecutionsCommand, ListAssociationVersionsCommand } from "@aws-sdk/client-ssm";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, List, Page, Pill, Section, Segments, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Pencil, Play, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../lib/clients";
import { RUNNING, targetsText, tone, words } from "../../../lib/status";
import { applyNow, deleteAssociation, updateAssociation } from "../associations/actions";
import { AssociationFields } from "../associations/fields";

export const metadata: Metadata = { title: "Association" };

type Props = { searchParams: Promise<{ id?: string; tab?: string; execution?: string }> };

const paramLines = (p: Record<string, string[]> | undefined) =>
  Object.entries(p ?? {})
    .map(([k, v]) => `${k}=${v[0] ?? ""}${v.slice(1).map((l) => `\n  ${l}`).join("")}`)
    .join("\n");

export default async function Association({ searchParams }: Props) {
  const { id = "", tab = "executions", execution } = await searchParams;
  const back = { href: "/ssm/associations", label: "State Manager" };
  const c = await ssm();
  const data = await load(async () => (await c.send(new DescribeAssociationCommand({ AssociationId: id }))).AssociationDescription!);
  if (!data.ok) {
    return (
      <Page title="Association" icon={ICONS.association} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const a = data.value;
  const base = `/ssm/association?id=${id}`;
  const active = tab === "versions" ? "versions" : "executions";
  let body: React.ReactNode;
  if (active === "executions") {
    const runs = await load(() => c.send(new DescribeAssociationExecutionsCommand({ AssociationId: id, MaxResults: 50 })).then((r) => r.AssociationExecutions ?? []));
    const pick = execution ?? (runs.ok ? runs.value[0]?.ExecutionId : undefined);
    const targets = pick ? await load(() => c.send(new DescribeAssociationExecutionTargetsCommand({ AssociationId: id, ExecutionId: pick })).then((r) => r.AssociationExecutionTargets ?? [])) : null;
    body = runs.ok ? (
      <>
        {runs.value.some((r) => RUNNING.has(r.Status ?? "")) && <LiveRefresh />}
        <List
          label="Executions"
          empty={<Empty icon={ICONS.association}>Not applied yet</Empty>}
          rows={runs.value.map((r) => ({
            key: r.ExecutionId!,
            title: when(r.CreatedTime),
            subtitle: [`v${r.AssociationVersion}`, r.DetailedStatus, r.ResourceCountByStatus].filter(Boolean).join(" · "),
            href: `${base}&execution=${r.ExecutionId}`,
            meta: (
              <>
                {r.ExecutionId === pick && <Pill tone="info">shown</Pill>}
                <Status tone={tone(r.Status)}>{words(r.Status)}</Status>
              </>
            ),
          }))}
        />
        {targets && (
          <Section title="Targets" plain count={targets.ok ? targets.value.length : undefined}>
            {targets.ok ? (
              <List
                label="Execution targets"
                rows={targets.value.map((t) => ({
                  key: t.ResourceId!,
                  icon: <AwsIcon icon={ICONS.node} size={20} />,
                  title: t.ResourceId,
                  subtitle: [t.DetailedStatus, t.OutputSource?.OutputSourceType === "RunCommand" ? `command ${t.OutputSource.OutputSourceId}` : null].filter(Boolean).join(" · "),
                  href: t.OutputSource?.OutputSourceType === "RunCommand" && t.OutputSource.OutputSourceId ? `/ssm/command?id=${t.OutputSource.OutputSourceId}` : `/ssm/node?id=${encodeURIComponent(t.ResourceId!)}`,
                  meta: <Status tone={tone(t.Status)}>{words(t.Status)}</Status>,
                }))}
              />
            ) : (
              <ErrorNotice error={targets.error} />
            )}
          </Section>
        )}
      </>
    ) : (
      <ErrorNotice error={runs.error} />
    );
  } else {
    const versions = await load(() => c.send(new ListAssociationVersionsCommand({ AssociationId: id })).then((r) => r.AssociationVersions ?? []));
    body = versions.ok ? (
      <List
        label="Versions"
        rows={[...versions.value].reverse().map((v) => ({
          key: v.AssociationVersion!,
          icon: <span className="pill">v{v.AssociationVersion}</span>,
          title: v.AssociationName || v.Name,
          subtitle: [targetsText(v.Targets), v.ScheduleExpression, paramLines(v.Parameters).split("\n")[0]].filter(Boolean).join(" · "),
          meta: <span>{ago(v.CreatedDate)}</span>,
        }))}
      />
    ) : (
      <ErrorNotice error={versions.error} />
    );
  }
  return (
    <Page
      title={a.AssociationName || a.Name}
      icon={ICONS.association}
      back={back}
      subtitle={a.AssociationId}
      actions={
        <>
          <ActionForm action={applyNow.bind(null, id)} submit="Apply association now" icon={<Play size={16} />} testId="apply-association" />
          <Sheet title="Edit association" label="Edit association" icon={<Pencil size={16} />} testId="edit-association">
            <ActionForm action={updateAssociation.bind(null, id, a.AssociationVersion)} submit="Save" testId="edit-association">
              <AssociationFields
                documents={[]}
                fixedDocument
                defaults={{
                  name: a.AssociationName,
                  targets: a.Targets?.map((t) => `${t.Key}=${(t.Values ?? []).join(",")}`).join("\n"),
                  schedule: a.ScheduleExpression,
                  parameters: paramLines(a.Parameters),
                  maxConcurrency: a.MaxConcurrency,
                  maxErrors: a.MaxErrors,
                  severity: a.ComplianceSeverity === "UNSPECIFIED" ? "" : a.ComplianceSeverity,
                }}
              />
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteAssociation.bind(null, id, true)} submit="Delete association" icon={<Trash2 size={16} />} tone="danger" confirm="Delete this association?" testId="delete-association" />
        </>
      }
    >
      <Facts
        items={[
          ["Status", <Status key="s" tone={tone(a.Overview?.Status)}>{words(a.Overview?.Status ?? "Pending")}</Status>],
          a.Overview?.DetailedStatus && ["Detail", a.Overview.DetailedStatus],
          ["Document", <Link key="d" href={`/ssm/document?name=${encodeURIComponent(a.Name!)}`}>{a.Name}</Link>],
          ["Version", a.AssociationVersion],
          ["Targets", targetsText(a.Targets) || a.InstanceId],
          a.ScheduleExpression && ["Schedule", a.ScheduleExpression],
          a.LastExecutionDate && ["Last run", ago(a.LastExecutionDate)],
          a.LastSuccessfulExecutionDate && ["Last success", ago(a.LastSuccessfulExecutionDate)],
          a.ComplianceSeverity && a.ComplianceSeverity !== "UNSPECIFIED" && ["Compliance severity", a.ComplianceSeverity],
          a.Parameters && Object.keys(a.Parameters).length > 0 && ["Parameters", <code key="p" className="clip">{paramLines(a.Parameters)}</code>],
        ]}
      />
      <Segments
        label="Association"
        items={[
          { label: "Execution history", href: base, active: active === "executions" },
          { label: "Versions", href: `${base}&tab=versions`, active: active === "versions" },
        ]}
      />
      {body}
    </Page>
  );
}
