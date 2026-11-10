import { load } from "@mws-dashboard/aws";
import { DescribeTaskDefinitionCommand } from "@aws-sdk/client-ecs";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status, freeName } from "@mws-dashboard/ui";
import { Cpu, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, ecs } from "../../lib/clients";
import { clusters as listClusters, families as listFamilies, revisionOf, revisions } from "../../lib/ecs";
import { imageIcon } from "../../lib/presets";
import { NAME } from "../../lib/rules";
import { TaskDefinitionFields } from "../../lib/taskdef-form.tsx";
import { createCluster, deregisterTaskDefinition, registerTaskDefinition } from "./actions";

export const metadata: Metadata = { title: "ECS" };

type Props = { searchParams: Promise<{ tab?: string }> };

export default async function Clusters({ searchParams }: Props) {
  const { tab = "clusters" } = await searchParams;
  if (tab === "taskdefs") {
    const defs = await load(async () => {
      const client = await ecs();
      const families = await listFamilies("ACTIVE");
      return Promise.all(
        families.map(async (family) => {
          const arns = await revisions(family);
          // The latest revision's image and size: the row leads with its logo.
          const def = arns[0]
            ? await client
                .send(new DescribeTaskDefinitionCommand({ taskDefinition: arns[0] }))
                .then((r) => r.taskDefinition)
                .catch(() => undefined)
            : undefined;
          return { family, latest: arns[0], revisions: arns.length, image: def?.containerDefinitions?.[0]?.image, cpu: def?.cpu, memory: def?.memory };
        }),
      );
    });
    const families = defs.ok ? defs.value.map((d) => d.family) : [];
    const register = (
      <Sheet title="Create task definition" label="Create task definition" testId="register-task-definition">
        <ActionForm action={registerTaskDefinition} submit="Create" testId="register-task-definition">
          <TaskDefinitionFields families={families} />
        </ActionForm>
      </Sheet>
    );
    return (
      <Page title="Task definitions" actions={register}>
        {defs.ok ? (
          <List
            label="Task definitions"
            empty={<Empty icon={ICONS.task} action={register} />}
            rows={defs.value.map((d) => {
              const logo = imageIcon(d.image);
              return {
                key: d.family,
                icon: logo ? <AwsIcon icon={logo} size={24} /> : <AwsIcon icon={ICONS.task} size={24} />,
                title: d.family,
                subtitle: d.image && <code className="clip">{d.image}</code>,
                href: `/ecs/taskdef?family=${encodeURIComponent(d.family)}`,
                meta: (
                  <>
                    {d.cpu && d.memory && (
                      <Pill icon={<Cpu size={12} />} title="CPU · memory">
                        {Number(d.cpu) / 1024} vCPU · {Number(d.memory) / 1024} GB
                      </Pill>
                    )}
                    <Pill title={`${d.revisions} active revisions`}>rev {revisionOf(d.latest).split(":").pop()}</Pill>
                  </>
                ),
                actions: d.latest ? <ActionForm action={deregisterTaskDefinition.bind(null, d.latest)} submit={`Deregister ${d.latest.split("/").pop()}`} icon={<Trash2 size={15} />} tone="danger" confirm="Deregister the latest revision?" /> : undefined,
              };
            })}
          />
        ) : (
          <ErrorNotice error={defs.error} />
        )}
      </Page>
    );
  }
  const clusters = await load(() => listClusters());
  const clusterNames = clusters.ok ? clusters.value.map((c) => c.clusterName!) : [];
  const create = (
    <Sheet title="Create cluster" label="Create cluster" testId="create-ecs-cluster">
      <ActionForm action={createCluster} submit="Create" testId="create-ecs-cluster">
        <Field label="Cluster name" rule={NAME} taken={clusterNames} unique>
          <input name="name" required autoFocus defaultValue={freeName(clusterNames.includes("default") ? "cluster" : "default", clusterNames)} />
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
