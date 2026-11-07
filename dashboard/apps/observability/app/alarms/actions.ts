"use server";

import {
  DeleteAlarmsCommand,
  DisableAlarmActionsCommand,
  EnableAlarmActionsCommand,
  PutMetricAlarmCommand,
  SetAlarmStateCommand,
  type ComparisonOperator,
  type StateValue,
  type Statistic,
} from "@aws-sdk/client-cloudwatch";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";

import { cloudwatch } from "../../lib/clients";

/** Force an alarm into a state, as `aws cloudwatch set-alarm-state` does, to test its actions. */
export async function setState(name: string, state: StateValue) {
  return act(async () => {
    await (await cloudwatch()).send(new SetAlarmStateCommand({ AlarmName: name, StateValue: state, StateReason: "Set from the MWS console" }));
    return `${name} → ${state}`;
  }, "/alarms");
}

export async function createAlarm(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const action = text(form, "action");
    let Dimensions;
    try {
      Dimensions = text(form, "dims")
        ? text(form, "dims")
            .split(",")
            .map((d) => {
              const [Name, ...v] = d.split("=");
              return { Name: Name.trim(), Value: v.join("=").trim() };
            })
        : undefined;
    } catch {
      Dimensions = undefined;
    }
    await (await cloudwatch()).send(
      new PutMetricAlarmCommand({
        AlarmName: name,
        Namespace: required(form, "namespace", "Namespace"),
        MetricName: required(form, "metric", "Metric"),
        Dimensions,
        Statistic: (text(form, "stat") || "Sum") as Statistic,
        Period: Number(text(form, "period") || 60),
        EvaluationPeriods: Number(text(form, "evaluations") || 1),
        Threshold: Number(required(form, "threshold", "Threshold")),
        ComparisonOperator: (text(form, "comparison") || "GreaterThanThreshold") as ComparisonOperator,
        TreatMissingData: text(form, "missing") || undefined,
        AlarmActions: action ? [action] : undefined,
      }),
    );
    return `Created ${name}`;
  }, "/alarms");
}

export async function setActions(name: string, enabled: boolean) {
  return act(async () => {
    const client = await cloudwatch();
    if (enabled) await client.send(new EnableAlarmActionsCommand({ AlarmNames: [name] }));
    else await client.send(new DisableAlarmActionsCommand({ AlarmNames: [name] }));
    return enabled ? "Actions on" : "Actions muted";
  }, "/alarms");
}

export async function deleteAlarm(name: string) {
  return act(async () => {
    await (await cloudwatch()).send(new DeleteAlarmsCommand({ AlarmNames: [name] }));
    return `Deleted ${name}`;
  }, "/alarms");
}
