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
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";

import { cloudwatch } from "../../lib/clients";

/** Force an alarm into a state, as `aws cloudwatch set-alarm-state` does, to test its actions. */
export async function setState(name: string, state: StateValue) {
  return act(async () => {
    await (await cloudwatch()).send(new SetAlarmStateCommand({ AlarmName: name, StateValue: state, StateReason: "Set from the MWS console" }));
    return `${name} → ${state}`;
  }, "/alarms");
}

/** PutMetricAlarm's rejections that name no member in AWS's own words, on
 * the field they concern (with the constraint, so it can offer a repair). */
function onField(e: unknown, period: number): never {
  const message = e instanceof Error ? e.message : String(e);
  const limit = message.match(/EvaluationPeriods \* Period must be <= (\d+)/);
  if (limit) {
    const max = Math.max(1, Math.floor(Number(limit[1]) / period));
    throw new FieldError("evaluations", `At most ${max} at this period`, "range", { type: "integer", min: 1, max });
  }
  if (/Invalid arn syntax|Invalid action/.test(message)) throw new FieldError("action", "Not an alarm action ARN", "format", { format: "arn" });
  if (/parameter Period\b/.test(message)) throw new FieldError("period", message, "server");
  if (/parameter TreatMissingData\b/.test(message)) throw new FieldError("missing", message, "server");
  if (/parameter Namespace\b/.test(message)) throw new FieldError("namespace", "Required", "required");
  throw e;
}

export async function createAlarm(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const action = text(form, "action");
      const dims = text(form, "dims");
      // One Name=value per line or comma, as the field's `pairs` format reads them.
      const pairs = dims
        .split(/[\n,]+/)
        .map((p) => p.trim())
        .filter(Boolean)
        .map((p) => [p.slice(0, p.indexOf("=")).trim(), p.slice(p.indexOf("=") + 1).trim()] as const);
      const bad = pairs.find(([k, v]) => !k || !v);
      if (bad) throw new FieldError("dims", bad[0] ? `${bad[0]} needs a value` : "Like Name=value", "format", { format: "pairs" });
      const period = Number(text(form, "period") || 60);
      try {
        await (await cloudwatch()).send(
          new PutMetricAlarmCommand({
            AlarmName: name,
            Namespace: required(form, "namespace", "Namespace"),
            MetricName: required(form, "metric", "Metric"),
            Dimensions: pairs.length ? pairs.map(([Name, Value]) => ({ Name, Value })) : undefined,
            Statistic: (text(form, "stat") || "Sum") as Statistic,
            Period: period,
            EvaluationPeriods: Number(text(form, "evaluations") || 1),
            Threshold: Number(required(form, "threshold", "Threshold")),
            ComparisonOperator: (text(form, "comparison") || "GreaterThanThreshold") as ComparisonOperator,
            TreatMissingData: text(form, "missing") || undefined,
            AlarmActions: action ? [action] : undefined,
          }),
        );
      } catch (e) {
        onField(e, period);
      }
      return `Created ${name}`;
    },
    {
      revalidate: ["/alarms"],
      fields: {
        AlarmName: "name",
        Namespace: "namespace",
        MetricName: "metric",
        Dimensions: "dims",
        Statistic: "stat",
        ComparisonOperator: "comparison",
        Threshold: "threshold",
        Period: "period",
        EvaluationPeriods: "evaluations",
        TreatMissingData: "missing",
        AlarmActions: "action",
      },
    },
  );
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
