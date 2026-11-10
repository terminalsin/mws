"use server";

import {
  DeleteAlarmsCommand,
  DisableAlarmActionsCommand,
  EnableAlarmActionsCommand,
  PutCompositeAlarmCommand,
  PutMetricAlarmCommand,
  SetAlarmStateCommand,
  type ComparisonOperator,
  type MetricDataQuery,
  type StateValue,
  type Statistic,
} from "@aws-sdk/client-cloudwatch";
import {
  act,
  FieldError,
  required,
  text,
  type ActionResult,
} from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { alarmHref, cloudwatch } from "../../lib/clients";

const PATHS = ["/alarms", "/alarms/alarm"];

/** Force an alarm into a state, as `aws cloudwatch set-alarm-state` does, to test its actions. */
export async function setState(name: string, state: StateValue) {
  return act(
    async () => {
      await (
        await cloudwatch()
      ).send(
        new SetAlarmStateCommand({
          AlarmName: name,
          StateValue: state,
          StateReason: "Set from the MWS console",
        }),
      );
      return `${name} → ${state}`;
    },
    ...PATHS,
  );
}

/** The same, with a reason of the person's own (the alarm detail's sheet). */
export async function setStateWithReason(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const state = required(form, "state", "State") as StateValue;
      await (
        await cloudwatch()
      ).send(
        new SetAlarmStateCommand({
          AlarmName: name,
          StateValue: state,
          StateReason: text(form, "reason") || "Set from the MWS console",
        }),
      );
      return `${name} → ${state}`;
    },
    {
      revalidate: PATHS,
      fields: { StateValue: "state", StateReason: "reason" },
    },
  );
}

/** PutMetricAlarm's rejections that name no member in AWS's own words, on
 * the field they concern (with the constraint, so it can offer a repair). */
function onField(e: unknown, period: number, form: FormData): never {
  const message = e instanceof Error ? e.message : String(e);
  const limit = message.match(/EvaluationPeriods \* Period must be <= (\d+)/);
  if (limit) {
    const max = Math.max(1, Math.floor(Number(limit[1]) / period));
    throw new FieldError(
      "evaluations",
      `At most ${max} at this period`,
      "range",
      { type: "integer", min: 1, max },
    );
  }
  if (/DatapointsToAlarm/.test(message))
    throw new FieldError("datapoints", message, "server");
  if (/Invalid arn syntax|Invalid action/.test(message)) {
    // The field whose ARNs the message names (alarm, OK or insufficient data).
    const field =
      ["ok", "insufficient"].find((f) =>
        arns(form, f).some((a) => message.includes(a)),
      ) ?? "action";
    throw new FieldError(field, "Not an alarm action ARN", "format", {
      format: "arn",
    });
  }
  if (/parameter Period\b/.test(message))
    throw new FieldError("period", message, "server");
  if (/parameter TreatMissingData\b/.test(message))
    throw new FieldError("missing", message, "server");
  if (/parameter Namespace\b/.test(message))
    throw new FieldError("namespace", "Required", "required");
  if (/ExtendedStatistic|Statistic/.test(message))
    throw new FieldError("stat", message, "server");
  if (/Metrics|Expression/.test(message))
    throw new FieldError("metrics", message, "server");
  throw e;
}

/** ARNs in a textarea: one per line or comma. */
const arns = (form: FormData, name: string) =>
  text(form, name)
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);

/** Name=value lines (dimensions, tags), as the `pairs`/`tags` formats read them. */
function pairs(form: FormData, field: string) {
  const out = text(form, field)
    .split(/[\n,]+/)
    .map((p) => p.trim())
    .filter(Boolean)
    .map(
      (p) =>
        [
          p.slice(0, p.indexOf("=")).trim(),
          p.slice(p.indexOf("=") + 1).trim(),
        ] as const,
    );
  const bad = out.find(([k, v]) => !k || (field === "dims" && !v));
  if (bad)
    throw new FieldError(
      field,
      bad[0] ? `${bad[0]} needs a value` : "Like Name=value",
      "format",
      { format: "pairs" },
    );
  return out;
}

const STATS = ["SampleCount", "Average", "Sum", "Minimum", "Maximum"];

/** Create or update a metric alarm (PutMetricAlarm replaces the whole alarm,
 * so the edit form sends every setting it shows). */
export async function saveAlarm(
  editing: string | null,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const name = editing ?? required(form, "name", "Name");
      const period = Number(text(form, "period") || 60);
      const stat = text(form, "stat") || "Sum";
      const math = text(form, "metrics");
      let metrics: MetricDataQuery[] | undefined;
      if (math) {
        try {
          metrics = JSON.parse(math) as MetricDataQuery[];
        } catch {
          throw new FieldError("metrics", "Not valid JSON", "format", {
            format: "json",
          });
        }
      }
      const dims = math ? [] : pairs(form, "dims");
      const tags = editing ? [] : pairs(form, "tags");
      const datapoints = text(form, "datapoints");
      try {
        await (
          await cloudwatch()
        ).send(
          new PutMetricAlarmCommand({
            AlarmName: name,
            AlarmDescription: text(form, "description") || undefined,
            ...(metrics
              ? {
                  Metrics: metrics,
                  ThresholdMetricId: text(form, "thresholdMetric") || undefined,
                }
              : {
                  Namespace: required(form, "namespace", "Namespace"),
                  MetricName: required(form, "metric", "Metric"),
                  Dimensions: dims.length
                    ? dims.map(([Name, Value]) => ({ Name, Value }))
                    : undefined,
                  ...(STATS.includes(stat)
                    ? { Statistic: stat as Statistic }
                    : { ExtendedStatistic: stat }),
                  Period: period,
                  Unit: undefined,
                }),
            EvaluationPeriods: Number(text(form, "evaluations") || 1),
            DatapointsToAlarm: datapoints ? Number(datapoints) : undefined,
            Threshold: text(form, "thresholdMetric")
              ? undefined
              : Number(required(form, "threshold", "Threshold")),
            ComparisonOperator: (text(form, "comparison") ||
              "GreaterThanThreshold") as ComparisonOperator,
            TreatMissingData: text(form, "missing") || undefined,
            ActionsEnabled: editing
              ? text(form, "enabled") !== "off"
              : undefined,
            AlarmActions: arns(form, "action"),
            OKActions: arns(form, "ok"),
            InsufficientDataActions: arns(form, "insufficient"),
            Tags: tags.length
              ? tags.map(([Key, Value]) => ({ Key, Value }))
              : undefined,
          }),
        );
      } catch (e) {
        onField(e, period, form);
      }
      return editing ? `Saved ${name}` : `Created ${name}`;
    },
    {
      revalidate: PATHS,
      fields: {
        AlarmName: "name",
        AlarmDescription: "description",
        Namespace: "namespace",
        MetricName: "metric",
        Dimensions: "dims",
        Statistic: "stat",
        ExtendedStatistic: "stat",
        ComparisonOperator: "comparison",
        Threshold: "threshold",
        Period: "period",
        EvaluationPeriods: "evaluations",
        DatapointsToAlarm: "datapoints",
        TreatMissingData: "missing",
        AlarmActions: "action",
        OKActions: "ok",
        InsufficientDataActions: "insufficient",
        Metrics: "metrics",
        Tags: "tags",
      },
    },
  );
}

/** Create or update a composite alarm: a rule over other alarms' states. */
export async function saveComposite(
  editing: string | null,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const name = editing ?? required(form, "name", "Name");
      const tags = editing ? [] : pairs(form, "tags");
      const suppressor = text(form, "suppressor");
      await (
        await cloudwatch()
      ).send(
        new PutCompositeAlarmCommand({
          AlarmName: name,
          AlarmDescription: text(form, "description") || undefined,
          AlarmRule: required(form, "rule", "Rule"),
          ActionsEnabled: editing ? text(form, "enabled") !== "off" : undefined,
          AlarmActions: arns(form, "action"),
          OKActions: arns(form, "ok"),
          InsufficientDataActions: arns(form, "insufficient"),
          ActionsSuppressor: suppressor || undefined,
          ActionsSuppressorWaitPeriod: suppressor
            ? Number(text(form, "wait") || 60)
            : undefined,
          ActionsSuppressorExtensionPeriod: suppressor
            ? Number(text(form, "extension") || 60)
            : undefined,
          Tags: tags.length
            ? tags.map(([Key, Value]) => ({ Key, Value }))
            : undefined,
        }),
      );
      if (!editing) redirect(alarmHref(name));
      return `Saved ${name}`;
    },
    {
      revalidate: PATHS,
      fields: {
        AlarmName: "name",
        AlarmDescription: "description",
        AlarmRule: "rule",
        AlarmActions: "action",
        OKActions: "ok",
        InsufficientDataActions: "insufficient",
        ActionsSuppressor: "suppressor",
        ActionsSuppressorWaitPeriod: "wait",
        ActionsSuppressorExtensionPeriod: "extension",
        Tags: "tags",
      },
    },
  );
}

export async function setActions(name: string, enabled: boolean) {
  return act(
    async () => {
      const client = await cloudwatch();
      if (enabled)
        await client.send(
          new EnableAlarmActionsCommand({ AlarmNames: [name] }),
        );
      else
        await client.send(
          new DisableAlarmActionsCommand({ AlarmNames: [name] }),
        );
      return enabled ? "Actions on" : "Actions muted";
    },
    ...PATHS,
  );
}

export async function deleteAlarm(name: string, leave = false) {
  return act(async () => {
    await (
      await cloudwatch()
    ).send(new DeleteAlarmsCommand({ AlarmNames: [name] }));
    if (leave) redirect("/alarms");
    return `Deleted ${name}`;
  }, "/alarms");
}
