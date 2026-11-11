"use server";

import {
  AddTagsCommand,
  CreateTrailCommand,
  DeleteTrailCommand,
  PutEventSelectorsCommand,
  PutInsightSelectorsCommand,
  RemoveTagsCommand,
  StartLoggingCommand,
  StopLoggingCommand,
  UpdateTrailCommand,
  type AdvancedEventSelector,
  type DataResource,
  type EventSelector,
  type InsightType,
  type ReadWriteType,
} from "@aws-sdk/client-cloudtrail";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { bucketFrom, cloudTrailBucketPolicy } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { cloudtrail } from "../../lib/clients";

const PAGES = ["/cloudtrail", "/cloudtrail/trail"];

export async function createTrail(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Trail name");
    const client = await cloudtrail();
    await client.send(
      new CreateTrailCommand({
        Name,
        S3BucketName: await bucketFrom(form, "bucket", "aws-cloudtrail-logs", cloudTrailBucketPolicy),
        IsMultiRegionTrail: text(form, "multi") === "on",
        IncludeGlobalServiceEvents: true,
        EnableLogFileValidation: text(form, "validation") === "on",
      }),
    );
    if (text(form, "start") === "on") {
      await client.send(new StartLoggingCommand({ Name }));
      return `Trail ${Name} logging`;
    }
    return `Created ${Name}`;
  }, { revalidate: PAGES, fields: { Name: "name", InvalidTrailNameException: "name", S3BucketDoesNotExistException: "bucket", InsufficientS3BucketPolicyException: "bucket" } });
}

export async function setLogging(trail: string, on: boolean) {
  return act(async () => {
    const client = await cloudtrail();
    if (on) await client.send(new StartLoggingCommand({ Name: trail }));
    else await client.send(new StopLoggingCommand({ Name: trail }));
    return on ? "Logging" : "Stopped";
  }, ...PAGES);
}

export async function deleteTrail(trail: string, back: boolean) {
  return act(async () => {
    await (await cloudtrail()).send(new DeleteTrailCommand({ Name: trail }));
    if (back) redirect("/cloudtrail?tab=trails");
    return "Trail deleted";
  }, ...PAGES);
}

/** UpdateTrail: an empty value clears an optional setting, as in AWS. */
export async function updateTrail(trail: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const multi = text(form, "multi") === "on";
    const global = text(form, "global") === "on";
    if (multi && !global) throw new FieldError("global", "A multi-Region trail must include global service events", "server");
    await (await cloudtrail()).send(
      new UpdateTrailCommand({
        Name: trail,
        S3BucketName: required(form, "bucket", "S3 bucket"),
        S3KeyPrefix: text(form, "prefix"),
        SnsTopicName: text(form, "topic"),
        KmsKeyId: text(form, "kms"),
        // CloudTrail wants the log group ARN with its ":*" suffix; the picker gives it without.
        CloudWatchLogsLogGroupArn: ((v) => (v && !v.endsWith(":*") ? `${v}:*` : v))(text(form, "logGroup")),
        CloudWatchLogsRoleArn: text(form, "logRole"),
        IsMultiRegionTrail: multi,
        IncludeGlobalServiceEvents: global,
        EnableLogFileValidation: text(form, "validation") === "on",
      }),
    );
    return "Trail updated";
  }, {
    revalidate: PAGES,
    fields: {
      S3BucketName: "bucket",
      S3BucketDoesNotExistException: "bucket",
      InsufficientS3BucketPolicyException: "bucket",
      S3KeyPrefix: "prefix",
      InvalidS3PrefixException: "prefix",
      SnsTopicName: "topic",
      InvalidSnsTopicNameException: "topic",
      InsufficientSnsTopicPolicyException: "topic",
      KmsKeyId: "kms",
      KmsKeyNotFoundException: "kms",
      InvalidKmsKeyIdException: "kms",
      InsufficientEncryptionPolicyException: "kms",
      CloudWatchLogsLogGroupArn: "logGroup",
      InvalidCloudWatchLogsLogGroupArnException: "logGroup",
      CloudWatchLogsRoleArn: "logRole",
      InvalidCloudWatchLogsRoleArnException: "logRole",
      CloudWatchLogsDeliveryUnavailableException: "logRole",
    },
  });
}

const lines = (s: string) =>
  s
    .split(/[\n,]/)
    .map((l) => l.trim())
    .filter(Boolean);

/** Basic event selectors: management events plus S3 object and Lambda data events. */
export async function saveEventSelectors(trail: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const DataResources: DataResource[] = [];
    const s3 = lines(text(form, "s3"));
    if (s3.length) {
      DataResources.push({
        Type: "AWS::S3::Object",
        Values: s3.map((v) => (v === "*" || v === "all" ? "arn:aws:s3:::" : v.startsWith("arn:") ? v : `arn:aws:s3:::${v.replace(/^s3:\/\//, "")}${v.includes("/") ? "" : "/"}`)),
      });
    }
    const lambda = lines(text(form, "lambda"));
    if (lambda.length) DataResources.push({ Type: "AWS::Lambda::Function", Values: lambda.map((v) => (v === "*" || v === "all" ? "arn:aws:lambda" : v)) });
    const selector: EventSelector = {
      ReadWriteType: (text(form, "rw") || "All") as ReadWriteType,
      IncludeManagementEvents: text(form, "management") === "on",
      DataResources,
      ExcludeManagementEventSources: text(form, "excludeKms") === "on" ? ["kms.amazonaws.com"] : [],
    };
    await (await cloudtrail()).send(new PutEventSelectorsCommand({ TrailName: trail, EventSelectors: [selector] }));
    return "Event selectors saved";
  }, { revalidate: PAGES, fields: { "EventSelectors.DataResources.Values": "s3", InvalidEventSelectorsException: "s3" } });
}

/** Advanced event selectors as JSON (replaces basic selectors). */
export async function saveAdvancedSelectors(trail: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(required(form, "advanced", "Selectors"));
    } catch {
      throw new FieldError("advanced", "Invalid JSON", "format");
    }
    const list = (Array.isArray(parsed) ? parsed : [parsed]) as AdvancedEventSelector[];
    await (await cloudtrail()).send(new PutEventSelectorsCommand({ TrailName: trail, AdvancedEventSelectors: list }));
    return "Advanced event selectors saved";
  }, { revalidate: PAGES, fields: { AdvancedEventSelectors: "advanced", InvalidEventSelectorsException: "advanced" } });
}

export async function saveInsights(trail: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const types = form.getAll("insight").map(String) as InsightType[];
    await (await cloudtrail()).send(new PutInsightSelectorsCommand({ TrailName: trail, InsightSelectors: types.map((InsightType) => ({ InsightType })) }));
    return types.length ? "Insights on" : "Insights off";
  }, { revalidate: PAGES, fields: { InvalidInsightSelectorsException: "insight", InsufficientS3BucketPolicyException: "insight" } });
}

export async function saveTags(arn: string, current: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const tags = lines(text(form, "tags").replace(/,/g, "\n")).map((l) => {
      const [Key, ...rest] = l.split("=");
      return { Key: Key.trim(), Value: rest.join("=").trim() };
    });
    const client = await cloudtrail();
    const gone = current.filter((k) => !tags.some((t) => t.Key === k));
    if (gone.length) await client.send(new RemoveTagsCommand({ ResourceId: arn, TagsList: gone.map((Key) => ({ Key })) }));
    if (tags.length) await client.send(new AddTagsCommand({ ResourceId: arn, TagsList: tags }));
    return "Tags saved";
  }, { revalidate: PAGES, fields: { TagsList: "tags", InvalidTagParameterException: "tags", TagsLimitExceededException: "tags" } });
}
