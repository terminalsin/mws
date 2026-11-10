import { DescribeServicesCommand, ListServiceDeploymentsCommand, type ServiceDeploymentBrief, type Task } from "@aws-sdk/client-ecs";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { UpdateService } from "@mws-dashboard/ui/model/ecs";
import { Gauge, Globe, Network, Rocket, Shield, Trash2, Undo2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ecs } from "../../../lib/clients";
import { revisionOf, revisions, serviceHealth, familyOf, taskDefHref, tasks as listTasks } from "../../../lib/ecs";
import { deleteService, stopDeployment, updateService } from "../actions";
import { taskRow } from "../rows.tsx";

export const metadata: Metadata = { title: "Service" };

type Props = { searchParams: Promise<{ cluster?: string; name?: string; tab?: string; status?: string }> };

const ROLLOUT_TONE = { COMPLETED: "good", FAILED: "bad", IN_PROGRESS: "warn" } as const;

export default async function ServicePage({ searchParams }: Props) {
  const { cluster = "default", name = "", tab = "health", status = "RUNNING" } = await searchParams;
  const back = { href: `/ecs/cluster?name=${encodeURIComponent(cluster)}`, label: cluster };
  const here = `/ecs/service?cluster=${encodeURIComponent(cluster)}&name=${encodeURIComponent(name)}`;
  const desired = status === "STOPPED" ? "STOPPED" : "RUNNING";
  const data = await load(async () => {
    const client = await ecs();
    const out = await client.send(new DescribeServicesCommand({ cluster, services: [name], include: ["TAGS"] }));
    const s = out.services?.[0];
    if (!s) throw new Error(`Service ${name} was not found in ${cluster}`);
    const [tasks, history, revs] = await Promise.all([
      tab === "tasks" ? listTasks(cluster, desired, name) : Promise.resolve([] as Task[]),
      tab === "deployments"
        ? all((nextToken) => client.send(new ListServiceDeploymentsCommand({ cluster, service: name, nextToken })), (r) => r.serviceDeployments, (r) => r.nextToken).catch(() => [] as ServiceDeploymentBrief[])
        : Promise.resolve([] as ServiceDeploymentBrief[]),
      revisions(familyOf(s.taskDefinition)).catch(() => [] as string[]),
    ]);
    return { s, tasks, history, revs };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.ecsService} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { s, tasks, history, revs } = data.value;
  const health = serviceHealth(s);
  const net = s.networkConfiguration?.awsvpcConfiguration;
  const dc = s.deploymentConfiguration;
  const choices = revs.includes(s.taskDefinition!) ? revs : [s.taskDefinition!, ...revs];
  const deploying = (s.deployments?.length ?? 0) > 1 || s.deployments?.some((d) => d.rolloutState === "IN_PROGRESS");
  return (
    <Page
      title={name}
      icon={ICONS.ecsService}
      back={back}
      subtitle={s.serviceArn}
      actions={
        <>
          <Sheet title={`Update ${name}`} label="Update service" icon={<Rocket size={16} />} testId="update-service">
            <ActionForm action={updateService.bind(null, cluster, name, { taskDefinition: s.taskDefinition, desired: s.desiredCount })} submit="Update" testId="update-service">
              <Field label="Task definition revision" rule={UpdateService.taskDefinition}>
                <select name="taskDefinition" defaultValue={s.taskDefinition}>
                  {choices.map((d) => (
                    <option key={d} value={d}>
                      {revisionOf(d)}
                      {d === s.taskDefinition ? " (current)" : ""}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Desired tasks" rule={UpdateService.desiredCount}>
                <input name="desired" type="number" min={0} defaultValue={s.desiredCount} />
              </Field>
              <label className="check">
                <input type="checkbox" name="force" /> Force new deployment
              </label>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteService.bind(null, cluster, name, true)} submit="Delete service" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name} and stop its tasks?`} testId="delete-service" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Health", icon: <Gauge size={15} />, value: <Status tone={health.tone}>{health.text}</Status> },
          { label: "Tasks", icon: <AwsIcon icon={ICONS.task} size={16} />, value: `${s.runningCount} running · ${s.pendingCount} pending · ${s.desiredCount} desired` },
          { label: "Task definition", icon: <AwsIcon icon={ICONS.task} size={16} />, value: <Link href={taskDefHref(s.taskDefinition)}>{revisionOf(s.taskDefinition)}</Link> },
          (s.launchType || s.capacityProviderStrategy?.length) && {
            label: "Capacity",
            icon: <AwsIcon icon={ICONS.ecs} size={16} />,
            value: s.launchType ?? s.capacityProviderStrategy!.map((c) => c.capacityProvider).join(", "),
          },
          s.loadBalancers?.length && { label: "Load balancing", icon: <Network size={15} />, value: `${s.loadBalancers.length} target groups` },
        ]}
      />
      <Segments
        label="Service"
        items={[
          { label: "Health", href: here, active: tab === "health" },
          { label: "Tasks", href: `${here}&tab=tasks`, active: tab === "tasks", count: s.runningCount || undefined },
          { label: "Deployments", href: `${here}&tab=deployments`, active: tab === "deployments", count: deploying ? s.deployments?.length : undefined },
          { label: "Events", href: `${here}&tab=events`, active: tab === "events" },
          { label: "Networking", href: `${here}&tab=networking`, active: tab === "networking" },
          { label: "Configuration", href: `${here}&tab=configuration`, active: tab === "configuration" },
          { label: "Tags", href: `${here}&tab=tags`, active: tab === "tags", count: s.tags?.length || undefined },
        ]}
      />
      {tab === "health" && (
        <>
          <Section title="Deployments" plain>
            <List
              label="Current deployments"
              rows={(s.deployments ?? []).map((d) => ({
                key: d.id!,
                icon: <Rocket size={18} />,
                title: <Link href={taskDefHref(d.taskDefinition)}>{revisionOf(d.taskDefinition)}</Link>,
                subtitle: d.rolloutStateReason,
                meta: (
                  <>
                    <Pill tone={d.status === "PRIMARY" ? "info" : "neutral"}>{d.status?.toLowerCase()}</Pill>
                    <span title="Running / desired">
                      {d.runningCount}/{d.desiredCount}
                    </span>
                    {!!d.pendingCount && <Pill tone="warn">{d.pendingCount} pending</Pill>}
                    {!!d.failedTasks && <Pill tone="bad">{d.failedTasks} failed</Pill>}
                    {d.rolloutState && <Status tone={ROLLOUT_TONE[d.rolloutState] ?? "neutral"}>{d.rolloutState === "IN_PROGRESS" ? "in progress" : d.rolloutState.toLowerCase()}</Status>}
                    <span>{ago(d.updatedAt ?? d.createdAt)}</span>
                  </>
                ),
              }))}
            />
          </Section>
          <Section title="Recent events" plain>
            <List
              label="Recent events"
              empty={<Empty>No events</Empty>}
              rows={(s.events ?? []).slice(0, 5).map((e) => ({ key: e.id!, title: <span className="row-subtitle">{e.message}</span>, meta: <span title={when(e.createdAt)}>{ago(e.createdAt)}</span> }))}
            />
          </Section>
        </>
      )}
      {tab === "tasks" && (
        <>
          <Segments
            label="Desired status"
            items={[
              { label: "Running", href: `${here}&tab=tasks`, active: desired === "RUNNING" },
              { label: "Stopped", href: `${here}&tab=tasks&status=STOPPED`, active: desired === "STOPPED" },
            ]}
          />
          <List label="Tasks" empty={<Empty icon={ICONS.task} />} rows={tasks.map((t) => taskRow(cluster, t))} />
        </>
      )}
      {tab === "deployments" && (
        <List
          label="Deployments"
          empty={<Empty>No deployments</Empty>}
          rows={history.map((d) => ({
            key: d.serviceDeploymentArn!,
            icon: <Rocket size={18} />,
            title: d.serviceDeploymentArn!.split("/").pop(),
            subtitle: d.statusReason,
            meta: (
              <>
                <Status tone={d.status === "SUCCESSFUL" ? "good" : d.status === "IN_PROGRESS" || d.status === "PENDING" ? "warn" : d.status?.includes("FAIL") ? "bad" : "neutral"}>
                  {d.status === "IN_PROGRESS" ? "in progress" : (d.status?.toLowerCase().replace(/_/g, " ") ?? "")}
                </Status>
                <span title={when(d.startedAt ?? d.createdAt)}>{ago(d.startedAt ?? d.createdAt)}</span>
              </>
            ),
            actions:
              d.status === "IN_PROGRESS" || d.status === "PENDING" ? (
                <ActionForm action={stopDeployment.bind(null, d.serviceDeploymentArn!, "ROLLBACK")} submit="Roll back" icon={<Undo2 size={15} />} tone="danger" confirm="Roll this deployment back?" />
              ) : undefined,
          }))}
        />
      )}
      {tab === "events" && (
        <List
          label="Events"
          empty={<Empty>No events</Empty>}
          rows={(s.events ?? []).map((e) => ({ key: e.id!, title: <span className="row-subtitle">{e.message}</span>, meta: <span title={when(e.createdAt)}>{ago(e.createdAt)}</span> }))}
        />
      )}
      {tab === "networking" && (
        <>
          <Section title="Network">
            <Facts
              items={[
                net?.subnets?.length && ["Subnets", net.subnets.join(", ")],
                net?.securityGroups?.length && [
                  "Security groups",
                  <span key="g" className="chips">
                    {net.securityGroups.map((g) => (
                      <Link key={g} href={`/ec2/group?id=${encodeURIComponent(g)}`}>
                        <Pill icon={<Shield size={12} />}>{g}</Pill>
                      </Link>
                    ))}
                  </span>,
                ],
                net && ["Public IP", net.assignPublicIp === "ENABLED" ? <Pill key="p" tone="warn" icon={<Globe size={12} />}>Assigned</Pill> : "Not assigned"],
              ]}
            />
          </Section>
          <Section title="Load balancers" count={s.loadBalancers?.length ?? 0} plain>
            <List
              label="Load balancers"
              empty={<Empty>No load balancer</Empty>}
              rows={(s.loadBalancers ?? []).map((lb, n) => ({
                key: `${lb.targetGroupArn ?? lb.loadBalancerName}-${n}`,
                icon: <AwsIcon icon="resource/ElasticLoadBalancingApplicationLoadBalancer" size={22} />,
                title: lb.targetGroupArn ? lb.targetGroupArn.split("/")[1] : lb.loadBalancerName,
                href: lb.targetGroupArn ? `/elb/tg?arn=${encodeURIComponent(lb.targetGroupArn)}` : undefined,
                subtitle: `${lb.containerName}:${lb.containerPort}`,
              }))}
            />
          </Section>
        </>
      )}
      {tab === "configuration" && (
        <Section>
          <Facts
            items={[
              ["Status", s.status?.toLowerCase()],
              ["Scheduling", s.schedulingStrategy],
              s.platformVersion && ["Platform version", s.platformVersion],
              dc && ["Min / max healthy", `${dc.minimumHealthyPercent ?? 100}% / ${dc.maximumPercent ?? 200}%`],
              dc?.deploymentCircuitBreaker && ["Circuit breaker", dc.deploymentCircuitBreaker.enable ? `On${dc.deploymentCircuitBreaker.rollback ? ", rolls back" : ""}` : "Off"],
              s.deploymentController?.type && ["Deployment controller", s.deploymentController.type],
              s.healthCheckGracePeriodSeconds !== undefined && ["Health check grace", `${s.healthCheckGracePeriodSeconds}s`],
              s.placementStrategy?.length && ["Placement", s.placementStrategy.map((p) => `${p.type}${p.field ? `(${p.field})` : ""}`).join(", ")],
              s.placementConstraints?.length && ["Constraints", s.placementConstraints.map((p) => p.expression ?? p.type).join(", ")],
              ["ECS Exec", s.enableExecuteCommand ? "Enabled" : "Disabled"],
              s.roleArn && ["Service role", <Link key="r" href={`/iam/roles/${s.roleArn.split("/").pop()}`}>{s.roleArn.split("/").pop()}</Link>],
              ["Created", when(s.createdAt)],
            ]}
          />
        </Section>
      )}
      {tab === "tags" && ((s.tags ?? []).length ? <Tags tags={Object.fromEntries((s.tags ?? []).map((t) => [t.key ?? "", t.value ?? ""]))} /> : <Empty>No tags</Empty>)}
    </Page>
  );
}
