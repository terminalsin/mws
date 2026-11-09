import { DescribeServicesCommand, DescribeTasksCommand, ListServicesCommand, ListTaskDefinitionsCommand, ListTasksCommand } from "@aws-sdk/client-ecs";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Status } from "@mws-dashboard/ui";
import { Play, Plus, SlidersHorizontal, Square, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, ecs } from "../../../lib/clients";
import { createService, deleteCluster, deleteService, runTask, scaleService, stopTask } from "../actions";

export const metadata: Metadata = { title: "Cluster" };

type Props = { searchParams: Promise<{ name?: string; tab?: string }> };

export default async function Cluster({ searchParams }: Props) {
  const { name = "", tab = "services" } = await searchParams;
  const back = { href: "/ecs", label: "Clusters" };
  const base = `/ecs/cluster?name=${encodeURIComponent(name)}`;
  const data = await load(async () => {
    const client = await ecs();
    const [serviceArns, taskArns, defs] = await Promise.all([
      client.send(new ListServicesCommand({ cluster: name })).then((r) => r.serviceArns ?? []),
      client.send(new ListTasksCommand({ cluster: name })).then((r) => r.taskArns ?? []),
      client.send(new ListTaskDefinitionsCommand({ status: "ACTIVE", sort: "DESC" })).then((r) => r.taskDefinitionArns ?? []),
    ]);
    const [services, tasks] = await Promise.all([
      serviceArns.length ? client.send(new DescribeServicesCommand({ cluster: name, services: serviceArns.slice(0, 10) })).then((r) => r.services ?? []) : [],
      taskArns.length ? client.send(new DescribeTasksCommand({ cluster: name, tasks: taskArns.slice(0, 100) })).then((r) => r.tasks ?? []) : [],
    ]);
    return { services, tasks, defs };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.ecs} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { services, tasks, defs } = data.value;
  const defOptions = defs.map((d) => (
    <option key={d} value={d}>
      {d.split("/").pop()}
    </option>
  ));
  const launch = (
    <Field label="Launch type">
      <select name="launchType" defaultValue="FARGATE">
        <option value="FARGATE">Fargate</option>
        <option value="EC2">EC2</option>
      </select>
    </Field>
  );
  return (
    <Page
      title={name}
      icon={ICONS.ecs}
      back={back}
      actions={
        <>
          <Sheet title="Create service" label="Create service" icon={<Plus size={16} />} testId="create-service">
            <ActionForm action={createService.bind(null, name)} submit="Create service" testId="create-service">
              <Field label="Service name">
                <input name="name" required autoFocus />
              </Field>
              <Field label="Task definition">
                <select name="taskDefinition" required>
                  {defOptions}
                </select>
              </Field>
              <div className="form-row">
                <Field label="Desired tasks">
                  <input name="desired" type="number" min={0} defaultValue={1} />
                </Field>
                {launch}
              </div>
            </ActionForm>
          </Sheet>
          <Sheet title="Run task" label="Run task" icon={<Play size={16} />} testId="run-task">
            <ActionForm action={runTask.bind(null, name)} submit="Run" testId="run-task">
              <Field label="Task definition">
                <select name="taskDefinition" required>
                  {defOptions}
                </select>
              </Field>
              <div className="form-row">
                <Field label="Count">
                  <input name="count" type="number" min={1} max={10} defaultValue={1} />
                </Field>
                {launch}
              </div>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteCluster.bind(null, name)} submit="Delete cluster" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-ecs-cluster" />
        </>
      }
    >
      <Segments
        items={[
          { label: "Services", href: base, active: tab === "services", count: services.length || undefined },
          { label: "Tasks", href: `${base}&tab=tasks`, active: tab === "tasks", count: tasks.length || undefined },
        ]}
      />
      {tab === "tasks" ? (
        <List
          label="Tasks"
          empty={<Empty icon={ICONS.task} />}
          rows={tasks.map((t) => ({
            key: t.taskArn!,
            icon: <AwsIcon icon={ICONS.task} size={22} />,
            title: t.taskArn!.split("/").pop(),
            href: `/ecs/task?cluster=${encodeURIComponent(name)}&id=${t.taskArn!.split("/").pop()}`,
            subtitle: `${t.taskDefinitionArn?.split("/").pop()}${t.group?.startsWith("service:") ? ` · ${t.group.slice(8)}` : ""}`,
            meta: (
              <>
                {t.launchType && <Pill>{t.launchType}</Pill>}
                <Status tone={STATUS_TONE(t.lastStatus)}>{t.lastStatus?.toLowerCase()}</Status>
                <span>{ago(t.startedAt ?? t.createdAt)}</span>
              </>
            ),
            actions: t.lastStatus !== "STOPPED" ? <ActionForm action={stopTask.bind(null, name, t.taskArn!)} submit={`Stop ${t.taskArn!.split("/").pop()}`} icon={<Square size={15} />} tone="danger" /> : undefined,
          }))}
        />
      ) : (
        <List
          label="Services"
          empty={<Empty icon={ICONS.ecsService} />}
          rows={services.map((s) => {
            const healthy = s.runningCount === s.desiredCount;
            return {
              key: s.serviceArn!,
              icon: <AwsIcon icon={ICONS.ecsService} size={24} />,
              title: s.serviceName,
              subtitle: s.taskDefinition?.split("/").pop(),
              meta: (
                <>
                  {s.launchType && <Pill>{s.launchType}</Pill>}
                  <Status tone={healthy ? "good" : "warn"}>
                    {s.runningCount}/{s.desiredCount} tasks
                  </Status>
                  {!!s.pendingCount && <Pill tone="warn">{s.pendingCount} pending</Pill>}
                </>
              ),
              actions: (
                <>
                  <Sheet title={`Scale ${s.serviceName}`} label={`Scale ${s.serviceName}`} icon={<SlidersHorizontal size={15} />} testId={`scale-${s.serviceName}`}>
                    <ActionForm action={scaleService.bind(null, name, s.serviceName!)} submit="Update" testId={`scale-${s.serviceName}`}>
                      <Field label="Desired tasks">
                        <input name="desired" type="number" min={0} defaultValue={s.desiredCount} />
                      </Field>
                    </ActionForm>
                  </Sheet>
                  <ActionForm action={deleteService.bind(null, name, s.serviceName!)} submit={`Delete ${s.serviceName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.serviceName}?`} />
                </>
              ),
            };
          })}
        />
      )}
      {services.some((s) => s.events?.length) && tab === "services" && (
        <Section title="Events" plain>
          <List
            label="Events"
            rows={services
              .flatMap((s) => s.events ?? [])
              .sort((a, b) => (b.createdAt?.getTime() ?? 0) - (a.createdAt?.getTime() ?? 0))
              .slice(0, 8)
              .map((e) => ({ key: e.id!, title: <span className="row-subtitle">{e.message}</span>, meta: <span>{ago(e.createdAt)}</span> }))}
          />
        </Section>
      )}
    </Page>
  );
}
