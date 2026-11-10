"use server";

import {
  DeleteAnomalyDetectorCommand,
  DeleteInsightRulesCommand,
  DisableInsightRulesCommand,
  EnableInsightRulesCommand,
  PutInsightRuleCommand,
  DeleteMetricStreamCommand,
  PutAnomalyDetectorCommand,
  PutMetricDataCommand,
  PutMetricStreamCommand,
  StartMetricStreamsCommand,
  StopMetricStreamsCommand,
  type MetricStreamOutputFormat,
  type StandardUnit,
} from "@aws-sdk/client-cloudwatch";
import { roleFrom } from "@mws-dashboard/aws/auto";
import {
  act,
  checkFailures,
  FieldError,
  mws,
  required,
  text,
  type ActionResult,
} from "@mws-dashboard/aws";

import { cloudwatch } from "../../lib/clients";

/** Publish datapoints at MWS's clock: the quickest way to drive an alarm. */
export async function putMetricData(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const Namespace = required(form, "namespace", "Namespace");
      const MetricName = required(form, "metric", "Metric");
      const dims = text(form, "dims")
        .split(/[\n,]+/)
        .map((p) => p.trim())
        .filter(Boolean)
        .map((p) => ({
          Name: p.slice(0, p.indexOf("=")).trim(),
          Value: p.slice(p.indexOf("=") + 1).trim(),
        }));
      if (dims.some((d) => !d.Name || !d.Value))
        throw new FieldError("dims", "Like Name=value", "format", {
          format: "pairs",
        });
      const value = Number(required(form, "value", "Value"));
      const count = Math.max(
        1,
        Math.min(1000, Number(text(form, "count") || 1)),
      );
      const clock = await mws<{ now: string }>("/_mws/clock");
      const Timestamp = new Date(clock.now);
      const datum = {
        MetricName,
        Dimensions: dims.length ? dims : undefined,
        Timestamp,
        Unit: (text(form, "unit") || undefined) as StandardUnit | undefined,
      };
      // PutMetricData takes 1,000 values per call.
      await (
        await cloudwatch()
      ).send(
        new PutMetricDataCommand({
          Namespace,
          MetricData: [{ ...datum, Values: [value], Counts: [count] }],
        }),
      );
      return `Published ${count} × ${value} to ${MetricName}`;
    },
    {
      revalidate: ["/metrics", "/alarms"],
      fields: {
        Namespace: "namespace",
        MetricName: "metric",
        Dimensions: "dims",
        Value: "value",
        Values: "value",
        Unit: "unit",
        InvalidParameterValueException: "namespace",
      },
    },
  );
}

// Metric streams ---------------------------------------------------------------

/** The role CloudWatch assumes to put metric records into Firehose. */
const STREAM_ROLE = {
  name: "CloudWatchMetricStreamFirehoseRole",
  service: "streams.metrics.cloudwatch.amazonaws.com",
  statements: [
    {
      Effect: "Allow",
      Action: ["firehose:PutRecord", "firehose:PutRecordBatch"],
      Resource: "*",
    },
  ],
};

export async function putMetricStream(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const namespaces = text(form, "namespaces")
        .split(/[\s,]+/)
        .filter(Boolean);
      const role = await roleFrom(form, "role", STREAM_ROLE);
      const exclude = text(form, "mode") === "exclude";
      const filters = namespaces.map((Namespace) => ({ Namespace }));
      await (
        await cloudwatch()
      ).send(
        new PutMetricStreamCommand({
          Name: name,
          FirehoseArn: required(form, "firehose", "Firehose stream"),
          RoleArn: role,
          OutputFormat: (text(form, "format") ||
            "json") as MetricStreamOutputFormat,
          IncludeFilters: !exclude && filters.length ? filters : undefined,
          ExcludeFilters: exclude && filters.length ? filters : undefined,
        }),
      );
      return `Streaming ${name}`;
    },
    {
      revalidate: ["/metrics/streams"],
      fields: {
        Name: "name",
        FirehoseArn: "firehose",
        RoleArn: "role",
        OutputFormat: "format",
        IncludeFilters: "namespaces",
        ExcludeFilters: "namespaces",
      },
    },
  );
}

export async function setMetricStream(name: string, running: boolean) {
  return act(async () => {
    const c = await cloudwatch();
    if (running) await c.send(new StartMetricStreamsCommand({ Names: [name] }));
    else await c.send(new StopMetricStreamsCommand({ Names: [name] }));
    return running ? `Started ${name}` : `Stopped ${name}`;
  }, "/metrics/streams");
}

export async function deleteMetricStream(name: string) {
  return act(async () => {
    await (
      await cloudwatch()
    ).send(new DeleteMetricStreamCommand({ Name: name }));
    return `Deleted ${name}`;
  }, "/metrics/streams");
}

// Anomaly detection -----------------------------------------------------------

export async function putAnomalyDetector(
  ns: string,
  metric: string,
  dims: { Name: string; Value: string }[],
  stat: string,
) {
  return act(async () => {
    await (
      await cloudwatch()
    ).send(
      new PutAnomalyDetectorCommand({
        SingleMetricAnomalyDetector: {
          Namespace: ns,
          MetricName: metric,
          Dimensions: dims,
          Stat: stat,
        },
      }),
    );
    return "Anomaly detection on";
  }, "/metrics");
}

export async function deleteAnomalyDetector(
  ns: string,
  metric: string,
  dims: { Name: string; Value: string }[],
  stat: string,
) {
  return act(async () => {
    await (
      await cloudwatch()
    ).send(
      new DeleteAnomalyDetectorCommand({
        SingleMetricAnomalyDetector: {
          Namespace: ns,
          MetricName: metric,
          Dimensions: dims,
          Stat: stat,
        },
      }),
    );
    return "Anomaly detection off";
  }, "/metrics");
}

// Contributor Insights --------------------------------------------------------

export async function putInsightRule(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const definition = required(form, "definition", "Rule");
      try {
        JSON.parse(definition);
      } catch {
        throw new FieldError("definition", "Not valid JSON", "format", {
          format: "json",
        });
      }
      await (
        await cloudwatch()
      ).send(
        new PutInsightRuleCommand({
          RuleName: name,
          RuleDefinition: definition,
          RuleState: "ENABLED",
        }),
      );
      return `Created ${name}`;
    },
    {
      revalidate: ["/metrics/contributors"],
      fields: {
        RuleName: "name",
        RuleDefinition: "definition",
        InvalidParameterInputException: "definition",
      },
    },
  );
}

export async function setInsightRule(name: string, enabled: boolean) {
  return act(async () => {
    const c = await cloudwatch();
    const out = enabled
      ? await c.send(new EnableInsightRulesCommand({ RuleNames: [name] }))
      : await c.send(new DisableInsightRulesCommand({ RuleNames: [name] }));
    checkFailures(
      out.Failures,
      (f) =>
        `${f.FailureResource}: ${f.ExceptionType} ${f.FailureDescription ?? ""}`,
    );
    return enabled ? `Enabled ${name}` : `Disabled ${name}`;
  }, "/metrics/contributors");
}

export async function deleteInsightRule(name: string) {
  return act(async () => {
    const out = await (
      await cloudwatch()
    ).send(new DeleteInsightRulesCommand({ RuleNames: [name] }));
    checkFailures(
      out.Failures,
      (f) =>
        `${f.FailureResource}: ${f.ExceptionType} ${f.FailureDescription ?? ""}`,
    );
    return `Deleted ${name}`;
  }, "/metrics/contributors");
}
