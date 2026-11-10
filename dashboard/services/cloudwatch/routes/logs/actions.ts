"use server";

import {
  AssociateKmsKeyCommand,
  CreateExportTaskCommand,
  CreateLogGroupCommand,
  CreateLogStreamCommand,
  DeleteLogGroupCommand,
  DeleteLogStreamCommand,
  DeleteMetricFilterCommand,
  DeleteQueryDefinitionCommand,
  DeleteRetentionPolicyCommand,
  DeleteSubscriptionFilterCommand,
  DisassociateKmsKeyCommand,
  PutLogEventsCommand,
  PutLogGroupDeletionProtectionCommand,
  PutMetricFilterCommand,
  PutQueryDefinitionCommand,
  PutRetentionPolicyCommand,
  PutSubscriptionFilterCommand,
  ResourceAlreadyExistsException,
  StartQueryCommand,
  StopQueryCommand,
  TagResourceCommand,
  TestMetricFilterCommand,
  UntagResourceCommand,
  type Distribution,
  type QueryLanguage,
  type StandardUnit,
} from "@aws-sdk/client-cloudwatch-logs";
import {
  AddPermissionCommand,
  LambdaClient,
  ResourceConflictException,
} from "@aws-sdk/client-lambda";
import {
  act,
  client,
  FieldError,
  region,
  required,
  text,
  type ActionResult,
} from "@mws-dashboard/aws";
import { bucketFrom, roleFrom } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { logs } from "../../lib/clients";
import { clockNow } from "../../lib/events";

const GROUP = ["/logs", "/logs/group"];

export async function createGroup(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Log group name");
      const client = await logs();
      const tags = pairs(form, "tags");
      await client.send(
        new CreateLogGroupCommand({
          logGroupName: name,
          logGroupClass:
            text(form, "infrequent") === "on" ? "INFREQUENT_ACCESS" : undefined,
          kmsKeyId: text(form, "kms") || undefined,
          deletionProtectionEnabled:
            text(form, "protect") === "on" ? true : undefined,
          tags: tags.length ? Object.fromEntries(tags) : undefined,
        }),
      );
      const days = Number(text(form, "retention"));
      if (days)
        await client.send(
          new PutRetentionPolicyCommand({
            logGroupName: name,
            retentionInDays: days,
          }),
        );
      return `Created ${name}`;
    },
    {
      revalidate: ["/logs"],
      fields: {
        logGroupName: "name",
        retentionInDays: "retention",
        kmsKeyId: "kms",
        tags: "tags",
      },
    },
  );
}

export async function deleteGroup(name: string) {
  return act(async () => {
    await (
      await logs()
    ).send(new DeleteLogGroupCommand({ logGroupName: name }));
    redirect("/logs");
  });
}

export async function setRetention(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const days = Number(text(form, "retention"));
      const client = await logs();
      if (days)
        await client.send(
          new PutRetentionPolicyCommand({
            logGroupName: name,
            retentionInDays: days,
          }),
        );
      else
        await client.send(
          new DeleteRetentionPolicyCommand({ logGroupName: name }),
        );
      return days ? `Kept for ${days} days` : "Kept forever";
    },
    {
      revalidate: GROUP,
      fields: {
        retentionInDays: "retention",
        InvalidParameterException: "retention",
      },
    },
  );
}

/** Associate a KMS key with the group (new events are encrypted with it), or
 * disassociate it when the field is left empty. */
export async function setKmsKey(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const key = text(form, "kms");
      const client = await logs();
      if (key)
        await client.send(
          new AssociateKmsKeyCommand({ logGroupName: name, kmsKeyId: key }),
        );
      else
        await client.send(
          new DisassociateKmsKeyCommand({ logGroupName: name }),
        );
      return key ? "Encrypted with the key" : "Key removed";
    },
    {
      revalidate: GROUP,
      fields: {
        kmsKeyId: "kms",
        InvalidParameterException: "kms",
        AccessDeniedException: "kms",
        ResourceNotFoundException: "kms",
      },
    },
  );
}

export async function setDeletionProtection(name: string, enabled: boolean) {
  return act(
    async () => {
      await (
        await logs()
      ).send(
        new PutLogGroupDeletionProtectionCommand({
          logGroupIdentifier: name,
          deletionProtectionEnabled: enabled,
        }),
      );
      return enabled ? "Deletion protection on" : "Deletion protection off";
    },
    ...GROUP,
  );
}

/** Key=value lines. */
function pairs(form: FormData, field: string): [string, string][] {
  const out = text(form, field)
    .split(/[\n,]+/)
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) =>
      p.includes("=")
        ? ([
            p.slice(0, p.indexOf("=")).trim(),
            p.slice(p.indexOf("=") + 1).trim(),
          ] as [string, string])
        : ([p, ""] as [string, string]),
    );
  if (out.some(([k]) => !k))
    throw new FieldError(field, "Like key=value", "format", {
      format: "pairs",
    });
  return out;
}

export async function addTags(
  arn: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const tags = pairs(form, "tags");
      if (!tags.length) throw new FieldError("tags", "Required", "required");
      await (
        await logs()
      ).send(
        new TagResourceCommand({
          resourceArn: arn,
          tags: Object.fromEntries(tags),
        }),
      );
      return `Tagged ${tags.length}`;
    },
    { revalidate: ["/logs/group"], fields: { tags: "tags" } },
  );
}

export async function removeTag(arn: string, key: string) {
  return act(async () => {
    await (
      await logs()
    ).send(new UntagResourceCommand({ resourceArn: arn, tagKeys: [key] }));
    return `Removed ${key}`;
  }, "/logs/group");
}

/** Write one event at MWS's clock, creating the stream when it does not
 * exist yet; events PutLogEvents rejects (too old, too new, expired) fail. */
export async function writeEvent(
  group: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const client = await logs();
      const stream = text(form, "stream") || "console";
      try {
        await client.send(
          new CreateLogStreamCommand({
            logGroupName: group,
            logStreamName: stream,
          }),
        );
      } catch (e) {
        if (!(e instanceof ResourceAlreadyExistsException)) throw e;
      }
      const out = await client.send(
        new PutLogEventsCommand({
          logGroupName: group,
          logStreamName: stream,
          logEvents: [
            {
              timestamp: await clockNow(),
              message: required(form, "message", "Message"),
            },
          ],
        }),
      );
      const r = out.rejectedLogEventsInfo;
      if (r) {
        const why =
          r.expiredLogEventEndIndex !== undefined
            ? "older than the group's retention"
            : r.tooOldLogEventEndIndex !== undefined
              ? "more than 14 days old"
              : "more than 2 hours in the future";
        throw new Error(`Rejected: the event is ${why}`);
      }
      return `Wrote to ${stream}`;
    },
    {
      revalidate: ["/logs/group"],
      fields: { logStreamName: "stream", "logEvents.message": "message" },
    },
  );
}

export async function deleteStream(group: string, stream: string) {
  return act(async () => {
    await (
      await logs()
    ).send(
      new DeleteLogStreamCommand({
        logGroupName: group,
        logStreamName: stream,
      }),
    );
    return `Deleted ${stream}`;
  }, "/logs/group");
}

// Metric filters --------------------------------------------------------------

export async function putMetricFilter(
  group: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const dims = pairs(form, "dims");
      const def = text(form, "default");
      await (
        await logs()
      ).send(
        new PutMetricFilterCommand({
          logGroupName: group,
          filterName: name,
          filterPattern: text(form, "pattern"),
          metricTransformations: [
            {
              metricNamespace: required(form, "namespace", "Namespace"),
              metricName: required(form, "metric", "Metric"),
              metricValue: text(form, "value") || "1",
              defaultValue: def ? Number(def) : undefined,
              unit: (text(form, "unit") || undefined) as
                | StandardUnit
                | undefined,
              dimensions: dims.length ? Object.fromEntries(dims) : undefined,
            },
          ],
        }),
      );
      return `Saved ${name}`;
    },
    {
      revalidate: ["/logs/group"],
      fields: {
        filterName: "name",
        filterPattern: "pattern",
        metricNamespace: "namespace",
        metricName: "metric",
        metricValue: "value",
        defaultValue: "default",
        dimensions: "dims",
        unit: "unit",
        InvalidParameterException: "pattern",
      },
    },
  );
}

export async function deleteMetricFilter(group: string, name: string) {
  return act(async () => {
    await (
      await logs()
    ).send(
      new DeleteMetricFilterCommand({ logGroupName: group, filterName: name }),
    );
    return `Deleted ${name}`;
  }, "/logs/group");
}

/** TestMetricFilter: which of the sample lines the pattern matches, and the
 * values it extracts. */
export async function testMetricFilter(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const lines = text(form, "samples")
        .split("\n")
        .filter((l) => l.trim());
      if (!lines.length)
        throw new FieldError("samples", "Required", "required");
      const out = await (
        await logs()
      ).send(
        new TestMetricFilterCommand({
          filterPattern: text(form, "pattern"),
          logEventMessages: lines,
        }),
      );
      const matches = out.matches ?? [];
      return {
        ok: true,
        message: `${matches.length} of ${lines.length} match`,
        detail:
          matches
            .map(
              (m) =>
                `${m.eventNumber}: ${m.eventMessage}${m.extractedValues && Object.keys(m.extractedValues).length ? `  ${JSON.stringify(m.extractedValues)}` : ""}`,
            )
            .join("\n") || undefined,
      };
    },
    {
      fields: {
        filterPattern: "pattern",
        logEventMessages: "samples",
        InvalidParameterException: "pattern",
      },
    },
  );
}

// Subscription filters --------------------------------------------------------

/** The role CloudWatch Logs assumes to put records into Kinesis or Firehose. */
const SUBSCRIPTION_ROLE = {
  name: "CWLtoSubscriptionDestinationRole",
  service: "logs.amazonaws.com",
  statements: [
    {
      Effect: "Allow",
      Action: [
        "kinesis:PutRecord",
        "kinesis:PutRecords",
        "firehose:PutRecord",
        "firehose:PutRecordBatch",
      ],
      Resource: "*",
    },
  ],
};

export async function putSubscriptionFilter(
  group: string,
  groupArn: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const destination = required(form, "destination", "Destination");
      const service = destination.split(":")[2];
      if (!["lambda", "kinesis", "firehose", "logs"].includes(service ?? ""))
        throw new FieldError(
          "destination",
          "A Lambda function, Kinesis stream, Firehose stream or Logs destination ARN",
          "format",
          { format: "arn" },
        );
      const needsRole = service === "kinesis" || service === "firehose";
      const role = needsRole
        ? await roleFrom(form, "role", SUBSCRIPTION_ROLE)
        : undefined;
      if (service === "lambda") {
        // As the AWS console does: let CloudWatch Logs invoke the function.
        try {
          await (
            await client(LambdaClient)
          ).send(
            new AddPermissionCommand({
              FunctionName: destination,
              StatementId:
                `logs-${group.replace(/[^A-Za-z0-9_-]/g, "-")}-${name}`.slice(
                  0,
                  100,
                ),
              Action: "lambda:InvokeFunction",
              Principal: "logs.amazonaws.com",
              SourceArn: groupArn.endsWith(":*") ? groupArn : `${groupArn}:*`,
            }),
          );
        } catch (e) {
          if (!(e instanceof ResourceConflictException))
            throw new FieldError(
              "destination",
              e instanceof Error ? e.message : String(e),
              "missing",
            );
        }
      }
      await (
        await logs()
      ).send(
        new PutSubscriptionFilterCommand({
          logGroupName: group,
          filterName: name,
          filterPattern: text(form, "pattern"),
          destinationArn: destination,
          roleArn: role,
          distribution:
            service === "kinesis"
              ? ((text(form, "distribution") || "ByLogStream") as Distribution)
              : undefined,
        }),
      );
      return `Subscribed ${name}`;
    },
    {
      revalidate: ["/logs/group"],
      fields: {
        filterName: "name",
        filterPattern: "pattern",
        destinationArn: "destination",
        roleArn: "role",
        distribution: "distribution",
        LimitExceededException: "name",
      },
    },
  );
}

export async function deleteSubscriptionFilter(group: string, name: string) {
  return act(async () => {
    await (
      await logs()
    ).send(
      new DeleteSubscriptionFilterCommand({
        logGroupName: group,
        filterName: name,
      }),
    );
    return `Deleted ${name}`;
  }, "/logs/group");
}

// Export ---------------------------------------------------------------------

export async function exportToS3(
  group: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const hours = Number(text(form, "hours") || 24);
      const r = await region();
      // The bucket policy CloudWatch Logs needs to write the export.
      const bucket = await bucketFrom(
        form,
        "bucket",
        "logs-export",
        (b, account) => ({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: { Service: `logs.${r}.amazonaws.com` },
              Action: "s3:GetBucketAcl",
              Resource: `arn:aws:s3:::${b}`,
              Condition: { StringEquals: { "aws:SourceAccount": account } },
            },
            {
              Effect: "Allow",
              Principal: { Service: `logs.${r}.amazonaws.com` },
              Action: "s3:PutObject",
              Resource: `arn:aws:s3:::${b}/*`,
              Condition: { StringEquals: { "aws:SourceAccount": account } },
            },
          ],
        }),
      );
      const to = await clockNow();
      const out = await (
        await logs()
      ).send(
        new CreateExportTaskCommand({
          logGroupName: group,
          destination: bucket,
          destinationPrefix: text(form, "prefix") || undefined,
          from: to - hours * 3600_000,
          to: to + 1,
          taskName: text(form, "task") || undefined,
        }),
      );
      return `Export ${out.taskId} to ${bucket} started`;
    },
    {
      revalidate: ["/logs/group"],
      fields: {
        destination: "bucket",
        destinationPrefix: "prefix",
        taskName: "task",
        InvalidParameterException: "bucket",
      },
    },
  );
}

// Logs Insights ---------------------------------------------------------------

export async function startQuery(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const groups = form.getAll("groups").map(String).filter(Boolean);
      const language = (text(form, "language") || "CWLI") as QueryLanguage;
      if (!groups.length && language === "CWLI")
        throw new FieldError(
          "groups",
          "Pick at least one log group",
          "required",
        );
      const minutes = Number(text(form, "minutes") || 60);
      const end = await clockNow();
      const queryString = required(form, "query", "Query");
      const out = await (
        await logs()
      ).send(
        new StartQueryCommand({
          logGroupNames: groups.length ? groups : undefined,
          queryString,
          queryLanguage: language,
          startTime: Math.floor((end - minutes * 60_000) / 1000),
          endTime: Math.ceil(end / 1000) + 1,
          limit: Number(text(form, "limit") || 1000),
        }),
      );
      redirect(
        `/logs/insights?${new URLSearchParams({ id: out.queryId!, q: queryString, groups: groups.join(","), minutes: String(minutes), language })}`,
      );
    },
    {
      fields: {
        queryString: "query",
        logGroupNames: "groups",
        limit: "limit",
        MalformedQueryException: "query",
        InvalidParameterException: "query",
        ResourceNotFoundException: "groups",
      },
    },
  );
}

export async function stopQuery(id: string) {
  return act(async () => {
    await (await logs()).send(new StopQueryCommand({ queryId: id }));
    return "Stopped";
  }, "/logs/insights");
}

export async function saveQuery(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const groups = text(form, "groups").split(",").filter(Boolean);
      await (
        await logs()
      ).send(
        new PutQueryDefinitionCommand({
          name,
          queryString: required(form, "query", "Query"),
          logGroupNames: groups.length ? groups : undefined,
          queryDefinitionId: text(form, "id") || undefined,
          queryLanguage: (text(form, "language") || undefined) as
            | QueryLanguage
            | undefined,
        }),
      );
      return `Saved ${name}`;
    },
    {
      revalidate: ["/logs/insights"],
      fields: { name: "name", queryString: "query" },
    },
  );
}

export async function deleteQuery(id: string) {
  return act(async () => {
    await (
      await logs()
    ).send(new DeleteQueryDefinitionCommand({ queryDefinitionId: id }));
    return "Deleted";
  }, "/logs/insights");
}
