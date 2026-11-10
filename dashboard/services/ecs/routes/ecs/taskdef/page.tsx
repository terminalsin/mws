import { DescribeTaskDefinitionCommand } from "@aws-sdk/client-ecs";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, CopyValue, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { Box, Cpu, FilePlus2, MemoryStick, Network, Trash2, XCircle } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ecs } from "../../../lib/clients";
import { revisionOf, revisions } from "../../../lib/ecs";
import { imageIcon } from "../../../lib/presets";
import { deleteTaskDefinitions, deregisterTaskDefinition, registerRevision } from "../actions";

export const metadata: Metadata = { title: "Task definition" };

type Props = { searchParams: Promise<{ family?: string; revision?: string; tab?: string }> };

const READ_ONLY = ["taskDefinitionArn", "revision", "status", "requiresAttributes", "compatibilities", "registeredAt", "registeredBy", "deregisteredAt", "deleteRequestedAt"];

const roleLink = (arn: string | undefined) => (arn ? <Link href={`/iam/roles/${arn.split("/").pop()}`}>{arn.split("/").pop()}</Link> : undefined);

export default async function TaskDefinition({ searchParams }: Props) {
  const { family = "", revision, tab = "containers" } = await searchParams;
  const back = { href: "/ecs?tab=taskdefs", label: "Task definitions" };
  const data = await load(async () => {
    const client = await ecs();
    const [active, inactive] = await Promise.all([revisions(family, "ACTIVE"), revisions(family, "INACTIVE").catch(() => [] as string[])]);
    const target = revision ? `${family}:${revision}` : (active[0] ?? inactive[0] ?? family);
    const out = await client.send(new DescribeTaskDefinitionCommand({ taskDefinition: target, include: ["TAGS"] }));
    return { def: out.taskDefinition!, tags: out.tags ?? [], active, inactive };
  });
  if (!data.ok) {
    return (
      <Page title={family} icon={ICONS.task} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { def: d, tags, active, inactive } = data.value;
  const here = `/ecs/taskdef?family=${encodeURIComponent(family)}&revision=${d.revision}`;
  const editable = Object.fromEntries(Object.entries(d).filter(([k, v]) => !READ_ONLY.includes(k) && v !== undefined));
  const isActive = d.status === "ACTIVE";
  const all = [...active.map((a) => ({ arn: a, status: "ACTIVE" })), ...inactive.map((a) => ({ arn: a, status: "INACTIVE" }))].sort(
    (a, b) => Number(b.arn.split(":").pop()) - Number(a.arn.split(":").pop()),
  );
  return (
    <Page
      title={`${family}:${d.revision}`}
      icon={ICONS.task}
      back={back}
      subtitle={d.taskDefinitionArn}
      actions={
        <>
          <Sheet title="Create new revision" label="Create new revision" icon={<FilePlus2 size={16} />} testId="new-revision">
            <ActionForm action={registerRevision.bind(null, family)} submit="Create" testId="new-revision">
              <Field label="Task definition JSON" format="json">
                <textarea name="json" rows={22} spellCheck={false} className="code" defaultValue={JSON.stringify(editable, null, 2)} />
              </Field>
            </ActionForm>
          </Sheet>
          {isActive ? (
            <ActionForm action={deregisterTaskDefinition.bind(null, d.taskDefinitionArn!)} submit="Deregister" icon={<XCircle size={16} />} tone="danger" confirm={`Deregister ${revisionOf(d.taskDefinitionArn)}?`} testId="deregister-revision" />
          ) : (
            d.status === "INACTIVE" && <ActionForm action={deleteTaskDefinitions.bind(null, [d.taskDefinitionArn!])} submit="Delete" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${revisionOf(d.taskDefinitionArn)} for good?`} />
          )}
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.task} size={16} />, value: <Status tone={isActive ? "good" : "neutral"}>{d.status?.toLowerCase() ?? ""}</Status> },
          d.requiresCompatibilities?.length && { label: "Launch types", icon: <AwsIcon icon={ICONS.ecs} size={16} />, value: d.requiresCompatibilities.join(", ") },
          d.cpu && { label: "CPU", icon: <Cpu size={15} />, value: `${Number(d.cpu) / 1024} vCPU` },
          d.memory && { label: "Memory", icon: <MemoryStick size={15} />, value: `${Number(d.memory) / 1024} GB` },
          d.networkMode && { label: "Network mode", icon: <Network size={15} />, value: d.networkMode },
        ]}
      />
      <Segments
        label="Task definition"
        items={[
          { label: "Containers", href: here, active: tab === "containers", count: d.containerDefinitions?.length },
          { label: "Revisions", href: `${here}&tab=revisions`, active: tab === "revisions", count: all.length },
          { label: "JSON", href: `${here}&tab=json`, active: tab === "json" },
          { label: "Tags", href: `${here}&tab=tags`, active: tab === "tags", count: tags.length || undefined },
        ]}
      />
      {tab === "containers" && (
        <>
          <Section>
            <Facts
              items={[
                ["Task role", roleLink(d.taskRoleArn) ?? "None"],
                ["Task execution role", roleLink(d.executionRoleArn) ?? "None"],
                d.runtimePlatform && ["Platform", [d.runtimePlatform.operatingSystemFamily, d.runtimePlatform.cpuArchitecture].filter(Boolean).join(" · ")],
                ["Registered", `${when(d.registeredAt)}${d.registeredBy ? ` by ${d.registeredBy.split("/").pop()}` : ""}`],
              ]}
            />
          </Section>
          {(d.containerDefinitions ?? []).map((c) => {
            const log = c.logConfiguration;
            const group = log?.options?.["awslogs-group"];
            const logo = imageIcon(c.image);
            return (
              <Section key={c.name} title={c.name} icon={logo ? <AwsIcon icon={logo} size={16} /> : <Box size={16} aria-hidden />} actions={c.essential !== false ? <Pill tone="info">Essential</Pill> : undefined}>
                <Facts
                  items={[
                    ["Image", <CopyValue key="i" value={c.image} label="Copy image URI" />],
                    (c.cpu || c.memory || c.memoryReservation) && ["Resources", [c.cpu ? `${c.cpu} CPU units` : "", c.memory ? `${c.memory} MiB` : "", c.memoryReservation ? `${c.memoryReservation} MiB soft` : ""].filter(Boolean).join(" · ")],
                    c.portMappings?.length && ["Ports", c.portMappings.map((p) => `${p.containerPort}/${p.protocol ?? "tcp"}${p.hostPort && p.hostPort !== p.containerPort ? ` → ${p.hostPort}` : ""}`).join(", ")],
                    c.command?.length && ["Command", <code key="c">{c.command.join(" ")}</code>],
                    c.entryPoint?.length && ["Entry point", <code key="e">{c.entryPoint.join(" ")}</code>],
                    c.environment?.length && ["Environment", <code key="v">{c.environment.map((e) => `${e.name}=${e.value}`).join("\n")}</code>],
                    c.secrets?.length && ["Secrets", c.secrets.map((x) => x.name).join(", ")],
                    log && ["Logging", group ? <Link key="l" href={`/logs/group?name=${encodeURIComponent(group)}`}>{log.logDriver} · {group}</Link> : log.logDriver],
                    c.healthCheck?.command?.length && ["Health check", <code key="h">{c.healthCheck.command.join(" ")}</code>],
                  ]}
                />
              </Section>
            );
          })}
        </>
      )}
      {tab === "revisions" && (
        <List
          label="Revisions"
          empty={<Empty icon={ICONS.task} />}
          rows={all.map((r) => {
            const rev = r.arn.split(":").pop()!;
            return {
              key: r.arn,
              icon: <AwsIcon icon={ICONS.task} size={22} />,
              title: revisionOf(r.arn),
              href: `/ecs/taskdef?family=${encodeURIComponent(family)}&revision=${rev}`,
              meta: <Status tone={r.status === "ACTIVE" ? "good" : "neutral"}>{r.status.toLowerCase()}</Status>,
              actions:
                r.status === "ACTIVE" ? (
                  <ActionForm action={deregisterTaskDefinition.bind(null, r.arn)} submit={`Deregister ${revisionOf(r.arn)}`} icon={<XCircle size={15} />} tone="danger" confirm={`Deregister ${revisionOf(r.arn)}?`} />
                ) : (
                  <ActionForm action={deleteTaskDefinitions.bind(null, [r.arn])} submit={`Delete ${revisionOf(r.arn)}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${revisionOf(r.arn)} for good?`} />
                ),
            };
          })}
        />
      )}
      {tab === "json" && <CodeBlock value={JSON.stringify(d)} label="Task definition JSON" />}
      {tab === "tags" && (tags.length ? <Tags tags={Object.fromEntries(tags.map((t) => [t.key ?? "", t.value ?? ""]))} /> : <Empty>No tags</Empty>)}
      {d.deregisteredAt && <p className="muted">Deregistered {ago(d.deregisteredAt)}</p>}
    </Page>
  );
}
