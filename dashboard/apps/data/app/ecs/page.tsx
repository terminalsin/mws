import { DescribeClustersCommand, ListClustersCommand, ListTaskDefinitionFamiliesCommand, ListTaskDefinitionsCommand } from "@aws-sdk/client-ecs";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, ecs } from "../../lib/clients";
import { createCluster, deregisterTaskDefinition, registerTaskDefinition } from "./actions";

export const metadata: Metadata = { title: "ECS" };

type Props = { searchParams: Promise<{ tab?: string }> };

export default async function Clusters({ searchParams }: Props) {
  const { tab = "clusters" } = await searchParams;
  const client = await ecs();
  if (tab === "taskdefs") {
    const defs = await load(async () => {
      const families = (await client.send(new ListTaskDefinitionFamiliesCommand({ status: "ACTIVE" }))).families ?? [];
      return Promise.all(
        families.map(async (family) => {
          const arns = (await client.send(new ListTaskDefinitionsCommand({ familyPrefix: family, status: "ACTIVE", sort: "DESC" }))).taskDefinitionArns ?? [];
          return { family, latest: arns[0], revisions: arns.length };
        }),
      );
    });
    const register = (
      <Sheet title="Create task definition" label="Create task definition" testId="register-task-definition">
        <ActionForm action={registerTaskDefinition} submit="Create" testId="register-task-definition">
          <Field label="Family">
            <input name="family" required pattern="[A-Za-z0-9_\-]+" autoFocus />
          </Field>
          <Field label="Image URI">
            <input name="image" required placeholder="public.ecr.aws/nginx/nginx:latest" />
          </Field>
          <div className="form-row">
            <Field label="CPU">
              <select name="cpu" defaultValue="256">
                {["256", "512", "1024", "2048", "4096"].map((c) => (
                  <option key={c} value={c}>
                    {Number(c) / 1024} vCPU
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Memory (MiB)">
              <input name="memory" type="number" defaultValue={512} min={512} />
            </Field>
            <Field label="Port">
              <input name="port" type="number" min={1} max={65535} placeholder="80" />
            </Field>
          </div>
          <Field label="Command">
            <input name="command" placeholder="optional" />
          </Field>
        </ActionForm>
      </Sheet>
    );
    return (
      <Page title="Task definitions" actions={register}>
        {defs.ok ? (
          <List
            label="Task definitions"
            empty={<Empty icon={ICONS.task} action={register} />}
            rows={defs.value.map((d) => ({
              key: d.family,
              icon: <AwsIcon icon={ICONS.task} size={24} />,
              title: d.family,
              subtitle: d.latest?.split("/").pop(),
              meta: <span>{d.revisions} revisions</span>,
              actions: d.latest ? <ActionForm action={deregisterTaskDefinition.bind(null, d.latest)} submit={`Deregister ${d.latest.split("/").pop()}`} icon={<Trash2 size={15} />} tone="danger" confirm="Deregister the latest revision?" /> : undefined,
            }))}
          />
        ) : (
          <ErrorNotice error={defs.error} />
        )}
      </Page>
    );
  }
  const clusters = await load(async () => {
    const arns = (await client.send(new ListClustersCommand({}))).clusterArns ?? [];
    return arns.length ? ((await client.send(new DescribeClustersCommand({ clusters: arns }))).clusters ?? []) : [];
  });
  const create = (
    <Sheet title="Create cluster" label="Create cluster" testId="create-ecs-cluster">
      <ActionForm action={createCluster} submit="Create" testId="create-ecs-cluster">
        <Field label="Cluster name">
          <input name="name" required pattern="[A-Za-z0-9_\-]+" autoFocus />
        </Field>
        <label className="check">
          <input type="checkbox" name="insights" /> Container Insights
        </label>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Clusters" actions={create}>
      {clusters.ok ? (
        <List
          label="Clusters"
          empty={<Empty icon={ICONS.ecs} action={create} />}
          rows={clusters.value.map((c) => ({
            key: c.clusterArn!,
            icon: <AwsIcon icon={ICONS.ecs} size={24} />,
            title: c.clusterName,
            href: `/ecs/cluster?name=${encodeURIComponent(c.clusterName!)}`,
            meta: (
              <>
                <span title="Services">{c.activeServicesCount} services</span>
                <Pill tone={c.runningTasksCount ? "info" : "neutral"} title="Running tasks">
                  {c.runningTasksCount} running
                </Pill>
                {!!c.pendingTasksCount && <Pill tone="warn">{c.pendingTasksCount} pending</Pill>}
                <Status tone={STATUS_TONE(c.status)}>{c.status?.toLowerCase()}</Status>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={clusters.error} />
      )}
    </Page>
  );
}
