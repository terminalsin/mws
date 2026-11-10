"use server";

import {
  CancelMaintenanceWindowExecutionCommand,
  CreateMaintenanceWindowCommand,
  DeleteMaintenanceWindowCommand,
  DeregisterTargetFromMaintenanceWindowCommand,
  DeregisterTaskFromMaintenanceWindowCommand,
  RegisterTargetWithMaintenanceWindowCommand,
  RegisterTaskWithMaintenanceWindowCommand,
  UpdateMaintenanceWindowCommand,
  type MaintenanceWindowTaskType,
} from "@aws-sdk/client-ssm";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ssm } from "../../../lib/clients";
import { parseParameters, parseTargets } from "../../../lib/status";

const WINDOW_FIELDS = { Name: "name", Schedule: "schedule", Duration: "duration", Cutoff: "cutoff", ScheduleTimezone: "timezone", Description: "description", ValidationException: "schedule" };
const PAGE = "/ssm/window";

export async function createWindow(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await ssm()).send(
      new CreateMaintenanceWindowCommand({
        Name: required(form, "name", "Name"),
        Description: text(form, "description") || undefined,
        Schedule: required(form, "schedule", "Schedule"),
        ScheduleTimezone: text(form, "timezone") || undefined,
        Duration: Number(required(form, "duration", "Duration")),
        Cutoff: Number(text(form, "cutoff") || 0),
        AllowUnassociatedTargets: text(form, "unassociated") === "on",
      }),
    );
    redirect(`${PAGE}?id=${out.WindowId}`);
  }, { fields: WINDOW_FIELDS });
}

export async function setWindowEnabled(id: string, enabled: boolean) {
  return act(async () => {
    await (await ssm()).send(new UpdateMaintenanceWindowCommand({ WindowId: id, Enabled: enabled }));
    return enabled ? "Enabled" : "Disabled";
  }, PAGE, "/ssm/windows");
}

export async function updateWindow(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ssm()).send(
      new UpdateMaintenanceWindowCommand({
        WindowId: id,
        Name: required(form, "name", "Name"),
        Description: text(form, "description") || undefined,
        Schedule: required(form, "schedule", "Schedule"),
        ScheduleTimezone: text(form, "timezone") || undefined,
        Duration: Number(required(form, "duration", "Duration")),
        Cutoff: Number(text(form, "cutoff") || 0),
      }),
    );
    return "Saved";
  }, { revalidate: [PAGE, "/ssm/windows"], fields: WINDOW_FIELDS });
}

export async function deleteWindow(id: string) {
  return act(async () => {
    await (await ssm()).send(new DeleteMaintenanceWindowCommand({ WindowId: id }));
    redirect("/ssm/windows");
  });
}

export async function registerTarget(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ssm()).send(
      new RegisterTargetWithMaintenanceWindowCommand({
        WindowId: id,
        ResourceType: "INSTANCE",
        Targets: parseTargets(required(form, "targets", "Targets")),
        Name: text(form, "name") || undefined,
        OwnerInformation: text(form, "owner") || undefined,
      }),
    );
    return "Target registered";
  }, { revalidate: [PAGE], fields: { Targets: "targets", Name: "name", OwnerInformation: "owner", IdempotentParameterMismatch: "targets" } });
}

export async function deregisterTarget(id: string, target: string) {
  return act(async () => {
    await (await ssm()).send(new DeregisterTargetFromMaintenanceWindowCommand({ WindowId: id, WindowTargetId: target, Safe: true }));
    return "Target deregistered";
  }, PAGE);
}

/** Register a task: Run Command (a document and its parameters), Automation
 * (a runbook) or Lambda (a function), on the window's targets. */
export async function registerTask(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const type = (text(form, "type") || "RUN_COMMAND") as MaintenanceWindowTaskType;
    const arn = required(form, "task", "Task");
    const params = parseParameters(text(form, "parameters"));
    const targets = text(form, "targets");
    await (await ssm()).send(
      new RegisterTaskWithMaintenanceWindowCommand({
        WindowId: id,
        TaskType: type,
        TaskArn: arn,
        Name: text(form, "name") || undefined,
        Targets: type === "LAMBDA" && !targets ? undefined : parseTargets(targets || ""),
        Priority: Number(text(form, "priority") || 1),
        MaxConcurrency: text(form, "maxConcurrency") || (type === "LAMBDA" ? undefined : "1"),
        MaxErrors: text(form, "maxErrors") || (type === "LAMBDA" ? undefined : "0"),
        ServiceRoleArn: text(form, "role") || undefined,
        TaskInvocationParameters:
          type === "RUN_COMMAND"
            ? { RunCommand: { Parameters: params, Comment: text(form, "name") || undefined } }
            : type === "AUTOMATION"
              ? { Automation: { Parameters: params } }
              : type === "LAMBDA"
                ? { Lambda: text(form, "payload") ? { Payload: new TextEncoder().encode(text(form, "payload")) } : {} }
                : undefined,
      }),
    );
    return "Task registered";
  }, {
    revalidate: [PAGE],
    fields: { TaskArn: "task", Targets: "targets", Priority: "priority", ServiceRoleArn: "role", MaxConcurrency: "maxConcurrency", MaxErrors: "maxErrors", FeatureNotAvailableException: "type", InvalidParameters: "parameters" },
  });
}

export async function deregisterTask(id: string, task: string) {
  return act(async () => {
    await (await ssm()).send(new DeregisterTaskFromMaintenanceWindowCommand({ WindowId: id, WindowTaskId: task }));
    return "Task deregistered";
  }, PAGE);
}

export async function cancelExecution(id: string) {
  return act(async () => {
    await (await ssm()).send(new CancelMaintenanceWindowExecutionCommand({ WindowExecutionId: id }));
    return "Cancelling";
  }, PAGE);
}
