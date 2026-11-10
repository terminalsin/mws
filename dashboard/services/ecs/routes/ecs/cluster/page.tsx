import { DescribeClustersCommand, DescribeContainerInstancesCommand, ListContainerInstancesCommand, type Task } from "@aws-sdk/client-ecs";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Status, Tags, freeName } from "@mws-dashboard/ui";
import { CreateService, RunTask } from "@mws-dashboard/ui/model/ecs";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { Activity, Play, Plus, Server, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATUS_TONE, ecs } from "../../../lib/clients";
import { activeDefinitions, familyOf, revisionOf, serviceHealth, serviceHref, services as listServices, tasks as listTasks } from "../../../lib/ecs";
import { NAME } from "../../../lib/rules";
import { createService, deleteCluster, deleteService, runTask, updateClusterInsights } from "../actions";
import { taskRow } from "../rows.tsx";

export const metadata: Metadata = { title: "Cluster" };

type Props = { searchParams: Promise<{ name?: string; tab?: string; status?: string }> };

export default async function Cluster({ searchParams }: Props) {
  const { name = "", tab = "services", status = "RUNNING" } = await searchParams;
  const back = { href: "/ecs", label: "Clusters" };
  const base = `/ecs/cluster?name=${encodeURIComponent(name)}`;
  const desired = status === "STOPPED" ? "STOPPED" : "RUNNING";
  const data = await load(async () => {
    const client = await ecs();
    const [cluster, services, tasks, defs] = await Promise.all([
      client.send(new DescribeClustersCommand({ clusters: [name], include: ["SETTINGS", "STATISTICS", "TAGS", "CONFIGURATIONS"] })).then((r) => {
        const c = r.clusters?.[0];
        if (!c) throw new Error(r.failures?.[0]?.reason === "MISSING" ? `Cluster ${name} was not found` : (r.failures?.[0]?.reason ?? `Cluster ${name} was not found`));
        return c;
      }),
      listServices(name),
      tab === "tasks" ? listTasks(name, desired) : Promise.resolve([] as Task[]),
      activeDefinitions(),
    ]);
    const instances =
      tab === "infrastructure"
        ? await all((nextToken) => client.send(new ListContainerInstancesCommand({ cluster: name, nextToken })), (r) => r.containerInstanceArns, (r) => r.nextToken).then(async (arns) =>
            arns.length ? ((await client.send(new DescribeContainerInstancesCommand({ cluster: name, containerInstances: arns.slice(0, 100) }))).containerInstances ?? []) : [],
          )
        : [];
    return { cluster, services, tasks, defs, instances };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.ecs} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { cluster: c, services, tasks, defs, instances } = data.value;
  const serviceNames = services.map((s) => s.serviceName!);
  // With no task definition there is nothing to pick: point at where one is made.
  const defHint = defs.length ? undefined : (
    <Link href="/ecs?tab=taskdefs" className="inline-flex items-center gap-1 text-link hover:underline">
      <Plus size={13} /> Task definition
    </Link>
  );
  const defOptions = defs.map((d) => (
    <option key={d} value={revisionOf(d)}>
      {revisionOf(d)}
    </option>
  ));
  // Fargate is what nearly everyone wants; EC2 waits under More.
  const launch = (
    <MoreFields>
      <Field label="Launch type">
        <select name="launchType" defaultValue="FARGATE">
          <option value="FARGATE">Fargate</option>
          <option value="EC2">EC2</option>
        </select>
      </Field>
    </MoreFields>
  );
  const insights = c.settings?.find((s) => s.name === "containerInsights")?.value;
  return (
    <Page
      title={name}
      icon={ICONS.ecs}
      back={back}
      subtitle={c.clusterArn}
      actions={
        <>
          <Sheet title="Create service" label="Create service" icon={<Plus size={16} />} testId="create-service">
            <ActionForm action={createService.bind(null, name)} submit="Create service" testId="create-service">
              <Field label="Service name" rule={{ ...CreateService.serviceName, ...NAME }} taken={serviceNames} unique>
                <input name="name" required autoFocus defaultValue={defs.length ? freeName(familyOf(defs[0]), serviceNames) : undefined} />
              </Field>
              <Field label="Task definition" rule={CreateService.taskDefinition} hint={defHint}>
                <select name="taskDefinition" required>
                  {defOptions}
                </select>
              </Field>
              <Field label="Desired tasks" rule={CreateService.desiredCount}>
                <input name="desired" type="number" min={0} defaultValue={1} />
              </Field>
              {launch}
            </ActionForm>
          </Sheet>
          <Sheet title="Run task" label="Run task" icon={<Play size={16} />} testId="run-task">
            <ActionForm action={runTask.bind(null, name)} submit="Run" testId="run-task">
              <Field label="Task definition" rule={RunTask.taskDefinition} hint={defHint}>
                <select name="taskDefinition" required>
                  {defOptions}
                </select>
              </Field>
              <Field label="Count" rule={RunTask.count}>
                <input name="count" type="number" min={1} max={10} defaultValue={1} />
              </Field>
              {launch}
            </ActionForm>
          </Sheet>
          <ActionForm
            action={deleteCluster.bind(null, name)}
            submit="Delete cluster"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={services.length || c.runningTasksCount ? `${name} still has ${services.length} services and ${c.runningTasksCount ?? 0} running tasks; ECS refuses until they are gone. Delete anyway?` : `Delete ${name}?`}
            testId="delete-ecs-cluster"
          />
        </>
      }
    >
      <Segments
        items={[
          { label: "Services", href: base, active: tab === "services", count: services.length || undefined },
          { label: "Tasks", href: `${base}&tab=tasks`, active: tab === "tasks", count: c.runningTasksCount || undefined },
          { label: "Infrastructure", href: `${base}&tab=infrastructure`, active: tab === "infrastructure" },
          { label: "Configuration", href: `${base}&tab=configuration`, active: tab === "configuration" },
          { label: "Tags", href: `${base}&tab=tags`, active: tab === "tags", count: c.tags?.length || undefined },
        ]}
      />
      {tab === "tasks" && (
        <>
          <Segments
            label="Desired status"
            items={[
              { label: "Running", href: `${base}&tab=tasks`, active: desired === "RUNNING" },
              { label: "Stopped", href: `${base}&tab=tasks&status=STOPPED`, active: desired === "STOPPED" },
            ]}
          />
          <List label="Tasks" empty={<Empty icon={ICONS.task}>{desired === "STOPPED" ? "No stopped tasks" : undefined}</Empty>} rows={tasks.map((t) => taskRow(name, t))} />
        </>
      )}
      {tab === "services" && (
        <List
          label="Services"
          empty={<Empty icon={ICONS.ecsService} />}
          rows={services.map((s) => {
            const health = serviceHealth(s);
            return {
              key: s.serviceArn!,
              icon: <AwsIcon icon={ICONS.ecsService} size={24} />,
              title: s.serviceName,
              subtitle: revisionOf(s.taskDefinition),
              href: serviceHref(name, s.serviceName!),
              meta: (
                <>
                  {s.launchType && <Pill>{s.launchType}</Pill>}
                  <span title="Running / desired">
                    {s.runningCount}/{s.desiredCount} tasks
                  </span>
                  {!!s.pendingCount && <Pill tone="warn">{s.pendingCount} pending</Pill>}
                  {health.tone !== "good" && <Status tone={health.tone}>{health.text}</Status>}
                </>
              ),
              actions: (
                <ActionForm action={deleteService.bind(null, name, s.serviceName!, false)} submit={`Delete ${s.serviceName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.serviceName}?`} />
              ),
            };
          })}
        />
      )}
      {tab === "infrastructure" && (
        <>
          <Section title="Capacity providers" plain>
            <List
              label="Capacity providers"
              empty={<Empty>No capacity providers</Empty>}
              rows={(c.capacityProviders ?? []).map((p) => {
                const strategy = c.defaultCapacityProviderStrategy?.find((x) => x.capacityProvider === p);
                return {
                  key: p,
                  icon: <Server size={18} />,
                  title: p,
                  meta: strategy ? (
                    <span title="Default strategy">
                      weight {strategy.weight ?? 0}
                      {strategy.base ? ` · base ${strategy.base}` : ""}
                    </span>
                  ) : undefined,
                };
              })}
            />
          </Section>
          <Section title="Container instances" count={c.registeredContainerInstancesCount ?? instances.length} plain>
            <List
              label="Container instances"
              empty={<Empty>No container instances</Empty>}
              rows={instances.map((ci) => ({
                key: ci.containerInstanceArn!,
                icon: <AwsIcon icon="resource/AmazonEC2Instance" size={22} />,
                title: ci.ec2InstanceId ?? ci.containerInstanceArn!.split("/").pop(),
                href: ci.ec2InstanceId ? `/ec2/instance?id=${ci.ec2InstanceId}` : undefined,
                subtitle: ci.attributes?.find((a) => a.name === "ecs.instance-type")?.value,
                meta: (
                  <>
                    <span>{ci.runningTasksCount} running</span>
                    {!ci.agentConnected && <Pill tone="bad">agent disconnected</Pill>}
                    <Status tone={STATUS_TONE(ci.status)}>{ci.status?.toLowerCase() ?? ""}</Status>
                  </>
                ),
              }))}
            />
          </Section>
        </>
      )}
      {tab === "configuration" && (
        <Section
          actions={
            <ActionForm
              action={updateClusterInsights.bind(null, name, insights !== "enabled")}
              submit={insights === "enabled" ? "Turn off Container Insights" : "Turn on Container Insights"}
              icon={<Activity size={15} />}
            />
          }
        >
          <Facts
            items={[
              ["Status", <Status key="s" tone={STATUS_TONE(c.status)}>{c.status?.toLowerCase() ?? ""}</Status>],
              ["Container Insights", insights ?? "disabled"],
              ["Services", c.activeServicesCount ?? 0],
              ["Running tasks", c.runningTasksCount ?? 0],
              ["Pending tasks", c.pendingTasksCount ?? 0],
              c.configuration?.executeCommandConfiguration?.logging && ["ECS Exec logging", c.configuration.executeCommandConfiguration.logging],
              c.serviceConnectDefaults?.namespace && ["Service Connect namespace", c.serviceConnectDefaults.namespace],
            ]}
          />
        </Section>
      )}
      {tab === "tags" && ((c.tags ?? []).length ? <Tags tags={Object.fromEntries((c.tags ?? []).map((t) => [t.key ?? "", t.value ?? ""]))} /> : <Empty>No tags</Empty>)}
    </Page>
  );
}

