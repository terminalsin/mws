import {
  DescribeMaintenanceWindowExecutionTasksCommand,
  DescribeMaintenanceWindowExecutionsCommand,
  DescribeMaintenanceWindowScheduleCommand,
  DescribeMaintenanceWindowTargetsCommand,
  DescribeMaintenanceWindowTasksCommand,
  GetMaintenanceWindowCommand,
} from "@aws-sdk/client-ssm";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { RegisterTaskWithMaintenanceWindow } from "@mws-dashboard/ui/model/ssm";
import { Ban, Pause, Pencil, Play, Plus, Target, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ssm } from "../../../lib/clients";
import { RUNNING, targetsText, tone, words } from "../../../lib/status";
import { cancelExecution, deleteWindow, deregisterTarget, deregisterTask, registerTarget, registerTask, setWindowEnabled, updateWindow } from "../windows/actions";
import { WindowFields } from "../windows/fields";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

export const metadata: Metadata = { title: "Maintenance window" };

type Props = { searchParams: Promise<{ id?: string; tab?: string; execution?: string }> };

const TASK = RegisterTaskWithMaintenanceWindow;

export default async function Window({ searchParams }: Props) {
  const { id = "", tab = "targets", execution } = await searchParams;
  const back = { href: "/ssm/windows", label: "Maintenance Windows" };
  const c = await ssm();
  const data = await load(() => c.send(new GetMaintenanceWindowCommand({ WindowId: id })));
  if (!data.ok) {
    return (
      <Page title="Maintenance window" icon={ICONS.window} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const w = data.value;
  const base = `/ssm/window?id=${id}`;
  const tabs = [
    { id: "targets", label: "Targets" },
    { id: "tasks", label: "Tasks" },
    { id: "history", label: "History" },
    { id: "schedule", label: "Schedule" },
  ];
  const active = tabs.some((t) => t.id === tab) ? tab : "targets";
  let body: React.ReactNode = null;
  if (active === "targets") {
    const targets = await load(() => c.send(new DescribeMaintenanceWindowTargetsCommand({ WindowId: id })).then((r) => r.Targets ?? []));
    body = (
      <Section
        title="Targets"
        plain
        actions={
          <Sheet title="Register target" label="Register target" icon={<Target size={16} />} testId="register-target">
            <ActionForm action={registerTarget.bind(null, id)} submit="Register" testId="register-target">
              <Field label="Targets" hint="InstanceIds=i-1,i-2 or tag:env=prod (one a line)" member="Targets">
                <textarea name="targets" rows={2} required />
              </Field>
              <Field label="Name">
                <input name="name" />
              </Field>
              <Field label="Owner information">
                <input name="owner" />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {targets.ok ? (
          <List
            label="Targets"
            empty={<Empty>No targets</Empty>}
            rows={targets.value.map((t) => ({
              key: t.WindowTargetId!,
              icon: <Target size={18} aria-hidden />,
              title: t.Name || t.WindowTargetId,
              subtitle: [targetsText(t.Targets), t.OwnerInformation].filter(Boolean).join(" · "),
              actions: <ActionForm action={deregisterTarget.bind(null, id, t.WindowTargetId!)} submit={`Deregister ${t.Name || t.WindowTargetId}`} icon={<Trash2 size={15} />} tone="danger" confirm="Deregister this target?" />,
            }))}
          />
        ) : (
          <ErrorNotice error={targets.error} />
        )}
      </Section>
    );
  } else if (active === "tasks") {
    const tasks = await load(() => c.send(new DescribeMaintenanceWindowTasksCommand({ WindowId: id })).then((r) => r.Tasks ?? []));
    body = (
      <Section
        title="Tasks"
        plain
        actions={
          <Sheet title="Register task" label="Register task" icon={<Plus size={16} />} testId="register-task">
            <ActionForm action={registerTask.bind(null, id)} submit="Register" testId="register-task">
              <div className="form-row">
                <Field label="Type" rule={TASK.TaskType}>
                  <select name="type" defaultValue="RUN_COMMAND">
                    <option value="RUN_COMMAND">Run Command</option>
                    <option value="AUTOMATION">Automation</option>
                    <option value="LAMBDA">Lambda</option>
                  </select>
                </Field>
                <Field label="Priority" rule={TASK.Priority}>
                  <input name="priority" type="number" defaultValue={1} />
                </Field>
              </div>
              <Field label="Document, runbook or function ARN" rule={TASK.TaskArn}>
                <input name="task" required defaultValue="AWS-RunShellScript" />
              </Field>
              <Field label="Name" rule={TASK.Name}>
                <input name="name" />
              </Field>
              <Field label="Targets" hint="WindowTargetIds=<id> or InstanceIds=i-1 (one a line)" member="Targets">
                <textarea name="targets" rows={2} placeholder="WindowTargetIds=…" />
              </Field>
              <Field label="Parameters" hint="name=value, one a line; indented lines continue a list" member="Parameters">
                <textarea name="parameters" rows={3} className="code-editor" spellCheck={false} placeholder={"commands=echo {{RESOURCE_ID}}"} />
              </Field>
              <Field label="Lambda payload" format="json">
                <textarea name="payload" rows={2} className="code-editor" spellCheck={false} />
              </Field>
              <div className="form-row">
                <Field label="Concurrency" rule={TASK.MaxConcurrency}>
                  <input name="maxConcurrency" placeholder="1" />
                </Field>
                <Field label="Error threshold" rule={TASK.MaxErrors}>
                  <input name="maxErrors" placeholder="0" />
                </Field>
              </div>
              <Field label="Service role ARN" rule={TASK.ServiceRoleArn} format="arn">
                <ResourcePicker kind="iam-role" name="role" service="ssm.amazonaws.com" />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {tasks.ok ? (
          <List
            label="Tasks"
            empty={<Empty>No tasks</Empty>}
            rows={tasks.value.map((t) => ({
              key: t.WindowTaskId!,
              icon: <AwsIcon icon={t.Type === "AUTOMATION" ? ICONS.automation : t.Type === "LAMBDA" ? "service/AWSLambda" : ICONS.runCommand} size={20} />,
              title: t.Name || t.TaskArn,
              subtitle: [t.Type?.toLowerCase().replace("_", " "), t.TaskArn, targetsText(t.Targets)].filter(Boolean).join(" · "),
              meta: <Pill>priority {t.Priority}</Pill>,
              actions: <ActionForm action={deregisterTask.bind(null, id, t.WindowTaskId!)} submit={`Deregister task ${t.Name || t.WindowTaskId}`} icon={<Trash2 size={15} />} tone="danger" confirm="Deregister this task?" />,
            }))}
          />
        ) : (
          <ErrorNotice error={tasks.error} />
        )}
      </Section>
    );
  } else if (active === "history") {
    const runs = await load(() => c.send(new DescribeMaintenanceWindowExecutionsCommand({ WindowId: id, MaxResults: 50 })).then((r) => r.WindowExecutions ?? []));
    const pick = execution ?? (runs.ok ? runs.value[0]?.WindowExecutionId : undefined);
    const taskRuns = pick ? await load(() => c.send(new DescribeMaintenanceWindowExecutionTasksCommand({ WindowExecutionId: pick })).then((r) => r.WindowExecutionTaskIdentities ?? [])) : null;
    body = runs.ok ? (
      <>
        {runs.value.some((r) => RUNNING.has(r.Status ?? "")) && <LiveRefresh />}
        <List
          label="Executions"
          empty={<Empty icon={ICONS.window}>Not run yet</Empty>}
          rows={runs.value.map((r) => ({
            key: r.WindowExecutionId!,
            title: when(r.StartTime),
            subtitle: [r.WindowExecutionId, r.StatusDetails, r.EndTime && r.StartTime ? `${Math.round((r.EndTime.getTime() - r.StartTime.getTime()) / 1000)}s` : null].filter(Boolean).join(" · "),
            href: `${base}&tab=history&execution=${r.WindowExecutionId}`,
            meta: <Status tone={tone(r.Status)}>{words(r.Status)}</Status>,
            actions: RUNNING.has(r.Status ?? "") ? <ActionForm action={cancelExecution.bind(null, r.WindowExecutionId!)} submit="Cancel execution" icon={<Ban size={15} />} tone="danger" /> : undefined,
          }))}
        />
        {taskRuns && taskRuns.ok && taskRuns.value.length > 0 && (
          <Section title="Tasks run" plain count={taskRuns.value.length}>
            <List
              label="Task executions"
              rows={taskRuns.value.map((t) => ({
                key: t.TaskExecutionId!,
                icon: <AwsIcon icon={t.TaskType === "AUTOMATION" ? ICONS.automation : t.TaskType === "LAMBDA" ? "service/AWSLambda" : ICONS.runCommand} size={20} />,
                title: t.TaskArn,
                subtitle: [t.StatusDetails, t.StartTime ? ago(t.StartTime) : null].filter(Boolean).join(" · "),
                meta: <Status tone={tone(t.Status)}>{words(t.Status)}</Status>,
              }))}
            />
          </Section>
        )}
      </>
    ) : (
      <ErrorNotice error={runs.error} />
    );
  } else {
    const schedule = await load(() => c.send(new DescribeMaintenanceWindowScheduleCommand({ WindowId: id, MaxResults: 10 })).then((r) => r.ScheduledWindowExecutions ?? []));
    body = schedule.ok ? (
      <List
        label="Upcoming"
        empty={<Empty>Nothing scheduled</Empty>}
        rows={schedule.value.map((s) => ({ key: s.ExecutionTime!, title: when(s.ExecutionTime), subtitle: s.Name }))}
      />
    ) : (
      <ErrorNotice error={schedule.error} />
    );
  }
  return (
    <Page
      title={w.Name}
      icon={ICONS.window}
      back={back}
      subtitle={w.WindowId}
      actions={
        <>
          <ActionForm action={setWindowEnabled.bind(null, id, !w.Enabled)} submit={w.Enabled ? "Disable window" : "Enable window"} icon={w.Enabled ? <Pause size={16} /> : <Play size={16} />} />
          <Sheet title="Edit maintenance window" label="Edit maintenance window" icon={<Pencil size={16} />} testId="edit-window">
            <ActionForm action={updateWindow.bind(null, id)} submit="Save" testId="edit-window">
              <WindowFields d={{ name: w.Name, description: w.Description, schedule: w.Schedule, timezone: w.ScheduleTimezone, duration: w.Duration, cutoff: w.Cutoff }} />
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteWindow.bind(null, id)} submit="Delete maintenance window" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${w.Name}?`} testId="delete-window" />
        </>
      }
    >
      <Facts
        items={[
          ["State", <Status key="s" tone={w.Enabled ? "good" : "neutral"}>{w.Enabled ? "Enabled" : "Disabled"}</Status>],
          ["Schedule", `${w.Schedule}${w.ScheduleTimezone ? ` (${w.ScheduleTimezone})` : ""}`],
          ["Duration", `${w.Duration}h, stop new tasks ${w.Cutoff}h before the end`],
          w.Enabled && w.NextExecutionTime && ["Next run", when(w.NextExecutionTime)],
          w.Description && ["Description", w.Description],
          w.StartDate && ["Starts", w.StartDate],
          w.EndDate && ["Ends", w.EndDate],
          ["Unregistered targets", w.AllowUnassociatedTargets ? "Allowed" : "Not allowed"],
          ["Created", ago(w.CreatedDate)],
        ]}
      />
      <Segments label="Maintenance window" items={tabs.map((t) => ({ label: t.label, href: t.id === "targets" ? base : `${base}&tab=${t.id}`, active: t.id === active }))} />
      {body}
    </Page>
  );
}
