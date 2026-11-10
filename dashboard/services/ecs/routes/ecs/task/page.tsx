import { GetLogEventsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { DescribeTaskDefinitionCommand, DescribeTasksCommand } from "@aws-sdk/client-ecs";
import { ago, load } from "@mws-dashboard/aws";
import { SHELL_ACTIONS } from "@mws-dashboard/aws/shell";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Facts, List, Page, Pill, Section, Segments, Specs, Status } from "@mws-dashboard/ui";
import { FileExplorer, Terminal } from "@mws-dashboard/ui/console";
import { Box, Clock, Cpu, FolderTree, HeartPulse, LayoutDashboard, MemoryStick, Network, Power, ScrollText, Square, SquareTerminal, TriangleAlert } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATUS_TONE, ecs, logs } from "../../../lib/clients";
import { revisionOf, serviceHref, taskDefHref } from "../../../lib/ecs";
import { stopTask } from "../actions";

export const metadata: Metadata = { title: "Task" };

type Props = { searchParams: Promise<{ cluster?: string; id?: string; tab?: string; container?: string }> };

export default async function TaskPage({ searchParams }: Props) {
  const { cluster = "default", id = "", tab = "overview", container: picked } = await searchParams;
  const back = { href: `/ecs/cluster?name=${encodeURIComponent(cluster)}&tab=tasks`, label: cluster };
  const data = await load(async () => {
    const client = await ecs();
    const task = (await client.send(new DescribeTasksCommand({ cluster, tasks: [id] }))).tasks?.[0];
    if (!task) throw new Error(`Task ${id} was not found`);
    const def = (await client.send(new DescribeTaskDefinitionCommand({ taskDefinition: task.taskDefinitionArn }))).taskDefinition;
    return { task, def };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.task} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { task: t, def } = data.value;
  const containers = t.containers ?? [];
  const container = containers.find((c) => c.name === picked)?.name ?? containers[0]?.name ?? "";
  const running = t.lastStatus === "RUNNING";
  // Anything not yet told to stop can be stopped, PENDING included.
  const stoppable = t.desiredStatus !== "STOPPED";
  const stopping = t.desiredStatus === "STOPPED" && t.lastStatus !== "STOPPED";
  const service = t.group?.startsWith("service:") ? t.group.slice(8) : undefined;
  const eni = t.attachments?.find((a) => a.type === "ElasticNetworkInterface")?.details ?? [];
  const detail = (name: string) => eni.find((x) => x.name === name)?.value;
  const shell = running && t.enableExecuteCommand;
  const here = `/ecs/task?cluster=${encodeURIComponent(cluster)}&id=${id}`;
  const withContainer = (tabName: string) => `${here}&tab=${tabName}${container ? `&container=${encodeURIComponent(container)}` : ""}`;
  const target = { service: "ecs" as const, base: `/_aws/ecs/tasks/${cluster}/${id}/${container}` };

  // awslogs output, from CloudWatch Logs.
  const cdef = def?.containerDefinitions?.find((c) => c.name === container);
  const opts = cdef?.logConfiguration?.logDriver === "awslogs" ? cdef.logConfiguration.options : undefined;
  const group = opts?.["awslogs-group"];
  const stream = group && opts?.["awslogs-stream-prefix"] ? `${opts["awslogs-stream-prefix"]}/${container}/${id}` : undefined;
  const lines =
    tab === "logs" && group && stream
      ? await load(async () => (await (await logs()).send(new GetLogEventsCommand({ logGroupName: group, logStreamName: stream, startFromHead: false, limit: 1000 }))).events ?? [])
      : null;

  const tabs = [
    { label: <><LayoutDashboard size={15} aria-hidden /> Overview</>, href: here, active: tab === "overview" },
    ...(shell
      ? [
          { label: <><SquareTerminal size={15} aria-hidden /> Terminal</>, href: withContainer("terminal"), active: tab === "terminal" },
          { label: <><FolderTree size={15} aria-hidden /> Files</>, href: withContainer("files"), active: tab === "files" },
        ]
      : []),
    { label: <><ScrollText size={15} aria-hidden /> Logs</>, href: withContainer("logs"), active: tab === "logs" },
  ];
  const picker =
    containers.length > 1 && tab !== "overview" ? (
      <Segments
        label="Container"
        items={containers.map((c) => ({ label: c.name, href: `${here}&tab=${tab}&container=${encodeURIComponent(c.name!)}`, active: c.name === container }))}
      />
    ) : null;

  return (
    <Page
      title={id}
      icon={ICONS.task}
      back={back}
      subtitle={t.taskArn}
      actions={stoppable && <ActionForm action={stopTask.bind(null, cluster, t.taskArn!)} submit="Stop task" icon={<Square size={16} />} tone="danger" confirm={`Stop ${id}?`} testId="stop-task" />}
    >
      <Segments label="Task" items={tabs} />
      {picker}
      {tab === "terminal" && shell && <Terminal target={target} actions={SHELL_ACTIONS} host={container} />}
      {tab === "files" && shell && <FileExplorer target={target} actions={SHELL_ACTIONS} start="/" />}
      {tab === "logs" &&
        (lines === null ? (
          <span className="muted">This container does not send its output to CloudWatch Logs (awslogs).</span>
        ) : lines.ok ? (
          lines.value.length ? (
            <CodeBlock value={lines.value.map((e) => `${new Date(e.timestamp ?? 0).toISOString()}  ${e.message}`).join("\n")} label="Container logs" />
          ) : (
            <span className="muted">No output yet</span>
          )
        ) : (
          <ErrorNotice error={lines.error} />
        ))}
      {tab === "overview" && (
        <>
          <Specs
            items={[
              { label: "Status", icon: <Power size={15} />, value: <Status tone={stopping ? "warn" : STATUS_TONE(t.lastStatus)}>{stopping ? "stopping" : (t.lastStatus?.toLowerCase() ?? "")}</Status> },
              { label: "Task definition", icon: <AwsIcon icon={ICONS.task} size={16} />, value: <Link href={taskDefHref(t.taskDefinitionArn)}>{revisionOf(t.taskDefinitionArn)}</Link> },
              service && { label: "Service", icon: <AwsIcon icon={ICONS.ecsService} size={16} />, value: <Link href={serviceHref(cluster, service)}>{service}</Link> },
              t.healthStatus && t.healthStatus !== "UNKNOWN" && { label: "Health", icon: <HeartPulse size={15} />, value: <Pill tone={t.healthStatus === "HEALTHY" ? "good" : "bad"}>{t.healthStatus.toLowerCase()}</Pill> },
              t.launchType && { label: "Launch type", icon: <AwsIcon icon={ICONS.ecs} size={16} />, value: t.launchType },
              t.cpu && { label: "CPU", icon: <Cpu size={15} />, value: `${Number(t.cpu) / 1024} vCPU` },
              t.memory && { label: "Memory", icon: <MemoryStick size={15} />, value: `${t.memory} MiB` },
              (detail("privateIPv4Address") ?? containers[0]?.networkInterfaces?.[0]?.privateIpv4Address) && {
                label: "Private IP",
                icon: <Network size={15} />,
                value: detail("privateIPv4Address") ?? containers[0]?.networkInterfaces?.[0]?.privateIpv4Address,
              },
              { label: t.stoppedAt ? "Stopped" : "Started", icon: <Clock size={15} />, value: ago(t.stoppedAt ?? t.startedAt ?? t.createdAt) },
            ]}
          />
          {t.stoppedReason && (
            <div className="banner error" role="alert" data-testid="stopped-reason">
              <TriangleAlert size={14} /> {t.stopCode ? `${t.stopCode}: ` : ""}
              {t.stoppedReason}
            </div>
          )}
          {(eni.length > 0 || t.containerInstanceArn) && (
            <Section title="Networking">
              <Facts
                items={[
                  detail("subnetId") && ["Subnet", detail("subnetId")],
                  detail("networkInterfaceId") && ["Network interface", detail("networkInterfaceId")],
                  detail("macAddress") && ["MAC address", <code key="m">{detail("macAddress")}</code>],
                  t.availabilityZone && ["Availability Zone", t.availabilityZone],
                  t.containerInstanceArn && ["Container instance", t.containerInstanceArn.split("/").pop()],
                  t.capacityProviderName && ["Capacity provider", t.capacityProviderName],
                ]}
              />
            </Section>
          )}
          <List
            label="Containers"
            rows={containers.map((c) => ({
              key: c.name!,
              icon: <Box size={18} aria-hidden />,
              title: c.name,
              subtitle: c.reason ? (
                <span className="row-subtitle">{c.reason}</span>
              ) : (
                <code className="clip">
                  {c.image}
                  {c.networkBindings?.length ? ` · ${c.networkBindings.map((b) => `${b.hostPort ?? b.containerPort}→${b.containerPort}`).join(", ")}` : ""}
                </code>
              ),
              href: shell ? `${here}&tab=terminal&container=${encodeURIComponent(c.name!)}` : undefined,
              meta: (
                <>
                  {c.healthStatus && c.healthStatus !== "UNKNOWN" && <Pill tone={c.healthStatus === "HEALTHY" ? "good" : "bad"}>{c.healthStatus.toLowerCase()}</Pill>}
                  {c.exitCode !== undefined && <Pill tone={c.exitCode === 0 ? "neutral" : "bad"}>exit {c.exitCode}</Pill>}
                  <Status tone={STATUS_TONE(c.lastStatus)}>{c.lastStatus?.toLowerCase()}</Status>
                </>
              ),
            }))}
          />
        </>
      )}
    </Page>
  );
}
