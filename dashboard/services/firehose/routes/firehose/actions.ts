"use server";

import {
  CreateDeliveryStreamCommand,
  DeleteDeliveryStreamCommand,
  DescribeDeliveryStreamCommand,
  PutRecordBatchCommand,
  PutRecordCommand,
  StartDeliveryStreamEncryptionCommand,
  StopDeliveryStreamEncryptionCommand,
  TagDeliveryStreamCommand,
  UntagDeliveryStreamCommand,
  UpdateDestinationCommand,
  type CloudWatchLoggingOptions,
  type CompressionFormat,
  type ContentEncoding,
  type HECEndpointType,
  type HttpEndpointS3BackupMode,
  type S3DestinationConfiguration,
  type SplunkS3BackupMode,
} from "@aws-sdk/client-firehose";
import {
  FieldError,
  act,
  checkFailures,
  required,
  text,
  type ActionResult,
} from "@mws-dashboard/aws";
import {
  ROLES,
  bucketFrom,
  roleFrom,
  type RoleSpec,
} from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { firehose, streamHref } from "../../lib/clients";
import { lambdaProcessing } from "../../lib/firehose";

const num = (form: FormData, name: string, fallback?: number) => {
  const v = text(form, name);
  return v === "" ? fallback : Number(v);
};

/** Firehose's role: S3 and Kinesis access (the console's template), plus
 * invoking the transform function and writing its error logs. */
function role(stream: string, bucket: string): RoleSpec {
  const base = ROLES.firehose(stream, bucket);
  return {
    ...base,
    statements: [
      ...base.statements,
      {
        Effect: "Allow",
        Action: [
          "lambda:InvokeFunction",
          "lambda:GetFunctionConfiguration",
          "logs:CreateLogStream",
        ],
        Resource: "*",
      },
    ],
  };
}

function logging(
  form: FormData,
  stream: string,
): CloudWatchLoggingOptions | undefined {
  if (text(form, "logging") !== "on") return undefined;
  return {
    Enabled: true,
    LogGroupName: text(form, "logGroup") || `/aws/kinesisfirehose/${stream}`,
    LogStreamName: "DestinationDelivery",
  };
}

function tags(form: FormData) {
  return text(form, "tags")
    .split(/[\n,]+/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => ({
      Key: (l.includes("=") ? l.slice(0, l.indexOf("=")) : l).trim(),
      Value: l.includes("=") ? l.slice(l.indexOf("=") + 1).trim() : "",
    }));
}

export async function createDeliveryStream(
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const source = text(form, "source");
      const destination = text(form, "destination") || "s3";
      const bucketName = await bucketFrom(form, "bucket", "firehose");
      const bucket = bucketName.startsWith("arn:")
        ? bucketName
        : `arn:aws:s3:::${bucketName}`;
      const roleArn = await roleFrom(
        form,
        "role",
        role(name, bucket.replace(/^arn:aws:s3:::/, "")),
      );
      const processing = lambdaProcessing(text(form, "lambda") || undefined);
      const compression = (text(form, "compression") ||
        "UNCOMPRESSED") as CompressionFormat;
      const s3: S3DestinationConfiguration = {
        BucketARN: bucket,
        RoleARN: roleArn,
        Prefix: text(form, "prefix") || undefined,
        ErrorOutputPrefix: text(form, "errorPrefix") || undefined,
        BufferingHints: {
          IntervalInSeconds: num(form, "interval", 300),
          SizeInMBs: num(form, "size", 5),
        },
        CompressionFormat: compression,
      };
      const tagList = tags(form);
      const create = (await firehose()).send(
        new CreateDeliveryStreamCommand({
          DeliveryStreamName: name,
          DeliveryStreamType: source ? "KinesisStreamAsSource" : "DirectPut",
          KinesisStreamSourceConfiguration: source
            ? { KinesisStreamARN: source, RoleARN: roleArn }
            : undefined,
          DeliveryStreamEncryptionConfigurationInput:
            !source && text(form, "sse") === "on"
              ? { KeyType: "AWS_OWNED_CMK" }
              : undefined,
          Tags: tagList.length ? tagList : undefined,
          ...(destination === "http"
            ? {
                HttpEndpointDestinationConfiguration: {
                  EndpointConfiguration: {
                    Url: required(form, "url", "Endpoint URL"),
                    Name: text(form, "endpointName") || undefined,
                    AccessKey: text(form, "accessKey") || undefined,
                  },
                  RequestConfiguration: {
                    ContentEncoding: (text(form, "encoding") ||
                      "NONE") as ContentEncoding,
                  },
                  BufferingHints: {
                    IntervalInSeconds: num(form, "interval", 300),
                    SizeInMBs: Math.min(64, num(form, "size", 5)!),
                  },
                  RetryOptions: { DurationInSeconds: num(form, "retry", 300) },
                  S3BackupMode: (text(form, "httpBackup") ||
                    "FailedDataOnly") as HttpEndpointS3BackupMode,
                  S3Configuration: {
                    ...s3,
                    Prefix: text(form, "prefix") || undefined,
                  },
                  RoleARN: roleArn,
                  ProcessingConfiguration: processing,
                  CloudWatchLoggingOptions: logging(form, name),
                },
              }
            : destination === "splunk"
              ? {
                  SplunkDestinationConfiguration: {
                    HECEndpoint: required(form, "hec", "HEC endpoint"),
                    HECEndpointType: (text(form, "hecType") ||
                      "Raw") as HECEndpointType,
                    HECToken: text(form, "hecToken") || undefined,
                    RetryOptions: {
                      DurationInSeconds: num(form, "retry", 300),
                    },
                    S3BackupMode: (text(form, "splunkBackup") ||
                      "FailedEventsOnly") as SplunkS3BackupMode,
                    S3Configuration: s3,
                    ProcessingConfiguration: processing,
                    CloudWatchLoggingOptions: logging(form, name),
                  },
                }
              : {
                  ExtendedS3DestinationConfiguration: {
                    ...s3,
                    ProcessingConfiguration: processing,
                    CloudWatchLoggingOptions: logging(form, name),
                    S3BackupMode:
                      text(form, "backup") === "on" ? "Enabled" : "Disabled",
                    S3BackupConfiguration:
                      text(form, "backup") === "on"
                        ? {
                            BucketARN: bucket,
                            RoleARN: roleArn,
                            Prefix: "source-records/",
                          }
                        : undefined,
                    FileExtension: text(form, "extension") || undefined,
                  },
                }),
        }),
      );
      await create.catch((e: unknown) => {
        // Firehose reads the source stream as the role; a stream it cannot
        // reach is a problem with the source field, not the form.
        if (source && e instanceof Error && /Kinesis stream/.test(e.message))
          throw new FieldError("source", e.message, "missing");
        throw e;
      });
      redirect(streamHref(name));
    },
    { fields: FIELDS },
  );
}

/** Where the forms put each API member, for errors MWS returns. */
const FIELDS = {
  DeliveryStreamName: "name",
  KinesisStreamARN: "source",
  Prefix: "prefix",
  ErrorOutputPrefix: "errorPrefix",
  IntervalInSeconds: "interval",
  SizeInMBs: "size",
  CompressionFormat: "compression",
  Url: "url",
  AccessKey: "accessKey",
  HECEndpoint: "hec",
  HECToken: "hecToken",
  DurationInSeconds: "retry",
  LambdaArn: "lambda",
  ParameterValue: "lambda",
  FileExtension: "extension",
  LogGroupName: "logGroup",
  Tags: "tags",
};

/** UpdateDestination for the stream's (only) destination, at the version
 * the form was opened on, so a concurrent change is refused. */
export async function updateDestination(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const c = await firehose();
      const s = (
        await c.send(
          new DescribeDeliveryStreamCommand({ DeliveryStreamName: name }),
        )
      ).DeliveryStreamDescription!;
      const d = s.Destinations![0];
      const version = text(form, "version") || s.VersionId!;
      const processing = lambdaProcessing(text(form, "lambda") || undefined);
      const buffering = {
        IntervalInSeconds: num(form, "interval"),
        SizeInMBs: num(form, "size"),
      };
      const roleArn = text(form, "role") || undefined;
      const base = {
        DeliveryStreamName: name,
        CurrentDeliveryStreamVersionId: version,
        DestinationId: d.DestinationId!,
      };
      if (d.ExtendedS3DestinationDescription) {
        await c.send(
          new UpdateDestinationCommand({
            ...base,
            ExtendedS3DestinationUpdate: {
              RoleARN: roleArn,
              Prefix: text(form, "prefix"),
              ErrorOutputPrefix: text(form, "errorPrefix"),
              BufferingHints: buffering,
              CompressionFormat: (text(form, "compression") || undefined) as
                | CompressionFormat
                | undefined,
              ProcessingConfiguration: processing,
              CloudWatchLoggingOptions:
                text(form, "logging") === "on"
                  ? logging(form, name)
                  : { Enabled: false },
              FileExtension: text(form, "extension"),
            },
          }),
        );
      } else if (d.HttpEndpointDestinationDescription) {
        await c.send(
          new UpdateDestinationCommand({
            ...base,
            HttpEndpointDestinationUpdate: {
              EndpointConfiguration: {
                Url: required(form, "url", "Endpoint URL"),
                Name: text(form, "endpointName") || undefined,
                AccessKey: text(form, "accessKey") || undefined,
              },
              RequestConfiguration: {
                ContentEncoding: (text(form, "encoding") ||
                  "NONE") as ContentEncoding,
              },
              BufferingHints: buffering,
              RetryOptions: { DurationInSeconds: num(form, "retry") },
              RoleARN: roleArn,
              ProcessingConfiguration: processing,
              CloudWatchLoggingOptions:
                text(form, "logging") === "on"
                  ? logging(form, name)
                  : { Enabled: false },
            },
          }),
        );
      } else if (d.SplunkDestinationDescription) {
        await c.send(
          new UpdateDestinationCommand({
            ...base,
            SplunkDestinationUpdate: {
              HECEndpoint: required(form, "hec", "HEC endpoint"),
              HECToken: text(form, "hecToken") || undefined,
              RetryOptions: { DurationInSeconds: num(form, "retry") },
              ProcessingConfiguration: processing,
              CloudWatchLoggingOptions:
                text(form, "logging") === "on"
                  ? logging(form, name)
                  : { Enabled: false },
            },
          }),
        );
      } else if (d.S3DestinationDescription) {
        await c.send(
          new UpdateDestinationCommand({
            ...base,
            S3DestinationUpdate: {
              RoleARN: roleArn,
              Prefix: text(form, "prefix"),
              ErrorOutputPrefix: text(form, "errorPrefix"),
              BufferingHints: buffering,
              CompressionFormat: (text(form, "compression") || undefined) as
                | CompressionFormat
                | undefined,
            },
          }),
        );
      } else {
        throw new Error(
          "This console edits S3, HTTP endpoint and Splunk destinations",
        );
      }
      return "Destination updated";
    },
    {
      revalidate: ["/firehose/stream", "/firehose"],
      fields: {
        ...FIELDS,
        RoleARN: "role",
        CurrentDeliveryStreamVersionId: "version",
        ConcurrentModificationException: "version",
      },
    },
  );
}

export async function deleteDeliveryStream(name: string) {
  return act(async () => {
    await (
      await firehose()
    ).send(new DeleteDeliveryStreamCommand({ DeliveryStreamName: name }));
    redirect("/firehose");
  });
}

export async function putFirehoseRecord(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const data =
        required(form, "data", "Data") +
        (text(form, "newline") === "off" ? "" : "\n");
      const out = await (
        await firehose()
      ).send(
        new PutRecordCommand({
          DeliveryStreamName: name,
          Record: { Data: new TextEncoder().encode(data) },
        }),
      );
      return `Record ${out.RecordId?.slice(0, 12)}… accepted`;
    },
    { revalidate: ["/firehose/stream"], fields: { Data: "data" } },
  );
}

/** PutRecordBatch: one record per line (each ending in a newline, as
 * line-delimited output needs). Per-record failures fail the form. */
export async function putRecordBatch(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const lines = required(form, "data", "Records")
        .split("\n")
        .filter((l) => l.trim());
      if (lines.length > 500)
        throw new FieldError("data", "At most 500 records per call", "range");
      const out = await (
        await firehose()
      ).send(
        new PutRecordBatchCommand({
          DeliveryStreamName: name,
          Records: lines.map((l) => ({
            Data: new TextEncoder().encode(`${l}\n`),
          })),
        }),
      );
      checkFailures(
        (out.RequestResponses ?? [])
          .map((r, i) => ({ ...r, i }))
          .filter((r) => r.ErrorCode),
        (r) => `Record ${r.i + 1}: ${r.ErrorCode} ${r.ErrorMessage ?? ""}`,
      );
      return `${lines.length} records accepted`;
    },
    { revalidate: ["/firehose/stream"], fields: { Records: "data" } },
  );
}

export async function setEncryption(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const c = await firehose();
      const kind = text(form, "keyType");
      if (!kind) {
        await c.send(
          new StopDeliveryStreamEncryptionCommand({ DeliveryStreamName: name }),
        );
        return "Turning encryption off";
      }
      await c.send(
        new StartDeliveryStreamEncryptionCommand({
          DeliveryStreamName: name,
          DeliveryStreamEncryptionConfigurationInput:
            kind === "CUSTOMER_MANAGED_CMK"
              ? {
                  KeyType: "CUSTOMER_MANAGED_CMK",
                  KeyARN: required(form, "key", "KMS key ARN"),
                }
              : { KeyType: "AWS_OWNED_CMK" },
        }),
      );
      return "Turning encryption on";
    },
    {
      revalidate: ["/firehose/stream"],
      fields: {
        KeyARN: "key",
        KeyType: "keyType",
        InvalidKMSResourceException: "key",
        InvalidArgumentException: "key",
      },
    },
  );
}

export async function addTags(
  name: string,
  _: ActionResult | null,
  form: FormData,
) {
  return act(
    async () => {
      const list = tags(form);
      if (!list.length) throw new FieldError("tags", "Required", "required");
      await (
        await firehose()
      ).send(
        new TagDeliveryStreamCommand({ DeliveryStreamName: name, Tags: list }),
      );
      return "Tagged";
    },
    { revalidate: ["/firehose/stream"], fields: { Tags: "tags" } },
  );
}

export async function removeTag(name: string, key: string) {
  return act(async () => {
    await (
      await firehose()
    ).send(
      new UntagDeliveryStreamCommand({
        DeliveryStreamName: name,
        TagKeys: [key],
      }),
    );
    return `Removed ${key}`;
  }, "/firehose/stream");
}
