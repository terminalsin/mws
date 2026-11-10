import type { Task } from "@aws-sdk/client-ecs";
import { ago } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Pill, Status } from "@mws-dashboard/ui";
import { Square } from "lucide-react";

import { ICONS, STATUS_TONE } from "../../lib/clients";
import { revisionOf, taskHref } from "../../lib/ecs";
import { stopTask } from "./actions";

/** A task row: the task, what it runs, and why it stopped. */
export function taskRow(cluster: string, t: Task) {
  const id = t.taskArn!.split("/").pop()!;
  const stopping = t.desiredStatus === "STOPPED" && t.lastStatus !== "STOPPED";
  return {
    key: t.taskArn!,
    icon: <AwsIcon icon={ICONS.task} size={22} />,
    title: id,
    href: taskHref(cluster, t.taskArn!),
    subtitle: t.stoppedReason ? (
      <span className="row-subtitle">{t.stoppedReason}</span>
    ) : (
      `${revisionOf(t.taskDefinitionArn)}${t.group?.startsWith("service:") ? ` · ${t.group.slice(8)}` : ""}`
    ),
    meta: (
      <>
        {t.launchType && <Pill>{t.launchType}</Pill>}
        {t.healthStatus && t.healthStatus !== "UNKNOWN" && <Pill tone={t.healthStatus === "HEALTHY" ? "good" : "bad"}>{t.healthStatus.toLowerCase()}</Pill>}
        <Status tone={stopping ? "warn" : STATUS_TONE(t.lastStatus)}>{stopping ? "stopping" : (t.lastStatus?.toLowerCase() ?? "")}</Status>
        <span>{ago(t.stoppedAt ?? t.startedAt ?? t.createdAt)}</span>
      </>
    ),
    actions:
      t.desiredStatus !== "STOPPED" ? <ActionForm action={stopTask.bind(null, cluster, t.taskArn!)} submit={`Stop ${id}`} icon={<Square size={15} />} tone="danger" /> : undefined,
  };
}

