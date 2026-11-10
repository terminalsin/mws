"use server";

import {
  CreateAccessGrantCommand,
  CreateAccessGrantsInstanceCommand,
  CreateAccessGrantsLocationCommand,
  CreateAccessPointCommand,
  CreateAccessPointForObjectLambdaCommand,
  CreateJobCommand,
  CreateMultiRegionAccessPointCommand,
  DeleteAccessGrantCommand,
  DeleteAccessGrantsInstanceCommand,
  DeleteAccessGrantsLocationCommand,
  DeleteAccessPointCommand,
  DeleteAccessPointForObjectLambdaCommand,
  DeleteMultiRegionAccessPointCommand,
  DeleteStorageLensConfigurationCommand,
  DeleteStorageLensGroupCommand,
  PutStorageLensConfigurationCommand,
  UpdateJobPriorityCommand,
  UpdateJobStatusCommand,
  type JobOperation,
  type Permission,
  DeleteAccessPointPolicyCommand,
  DeletePublicAccessBlockCommand,
  PutAccessPointPolicyCommand,
  PutPublicAccessBlockCommand,
  TagResourceCommand,
  UntagResourceCommand,
} from "@aws-sdk/client-s3-control";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { roleFrom } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { BATCH_ROLE, GRANTS_ROLE } from "../../lib/roles";
import { account, accessPointHref, control, controlHref } from "../../lib/s3";

const BPA = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"] as const;
const bpaOf = (form: FormData) => Object.fromEntries(BPA.map((k) => [k, text(form, k) === "on"]));

const tagLines = (value: string) =>
  value
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [Key, ...rest] = l.split("=");
      return { Key: Key.trim(), Value: rest.join("=").trim() };
    });

function policyFrom(form: FormData, field = "policy") {
  const policy = text(form, field);
  if (!policy) return "";
  try {
    JSON.parse(policy);
  } catch {
    throw new FieldError(field, "Invalid JSON", "format");
  }
  return policy;
}

// --- Account Block Public Access ---------------------------------------------

export async function saveAccountBpa(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const config = bpaOf(form);
    const AccountId = await account();
    const client = await control();
    if (BPA.every((k) => !config[k])) await client.send(new DeletePublicAccessBlockCommand({ AccountId }));
    else await client.send(new PutPublicAccessBlockCommand({ AccountId, PublicAccessBlockConfiguration: config }));
    return "Account Block Public Access saved";
  }, "/s3");
}

// --- Access points -------------------------------------------------------------

export async function createAccessPoint(bucket: string | null, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Name");
    const Bucket = bucket ?? required(form, "bucket", "Bucket");
    const vpc = text(form, "network") === "vpc" ? required(form, "vpc", "VPC") : "";
    await (await control()).send(
      new CreateAccessPointCommand({
        AccountId: await account(),
        Name,
        Bucket,
        VpcConfiguration: vpc ? { VpcId: vpc } : undefined,
        PublicAccessBlockConfiguration: bpaOf(form),
      }),
    );
    redirect(accessPointHref(Bucket, Name));
  }, { revalidate: ["/s3"], fields: { Name: "name", InvalidAccessPointName: "name", AccessPointAlreadyOwnedByYou: "name", Bucket: "bucket", NoSuchBucket: "bucket", "VpcConfiguration.VpcId": "vpc", InvalidVpcID: "vpc" } });
}

export async function deleteAccessPoint(name: string, back: string | null) {
  return act(async () => {
    await (await control()).send(new DeleteAccessPointCommand({ AccountId: await account(), Name: name }));
    if (back) redirect(back);
    return `Deleted access point ${name}`;
  }, "/s3", controlHref("access-points"));
}

export async function saveAccessPointPolicy(name: string, bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = policyFrom(form);
    const AccountId = await account();
    const client = await control();
    if (!policy) {
      await client.send(new DeleteAccessPointPolicyCommand({ AccountId, Name: name }));
      return "Policy removed";
    }
    await client.send(new PutAccessPointPolicyCommand({ AccountId, Name: name, Policy: policy }));
    return "Policy saved";
  }, { revalidate: [accessPointHref(bucket, name).split("?")[0]], fields: { Policy: "policy", MalformedPolicy: "policy", AccessDenied: "policy" } });
}

/** Tags of any S3 Control resource by ARN (access points, jobs, Storage Lens groups, grants). */
export async function saveControlTags(arn: string, current: string[], path: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const tags = tagLines(text(form, "tags"));
    const AccountId = await account();
    const client = await control();
    const gone = current.filter((k) => !tags.some((t) => t.Key === k));
    if (gone.length) await client.send(new UntagResourceCommand({ AccountId, ResourceArn: arn, TagKeys: gone }));
    if (tags.length) await client.send(new TagResourceCommand({ AccountId, ResourceArn: arn, Tags: tags }));
    return "Tags saved";
  }, { revalidate: [path], fields: { Tags: "tags", InvalidTag: "tags", TooManyTags: "tags" } });
}

// --- Object Lambda access points ------------------------------------------------

export async function createObjectLambda(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Name");
    await (await control()).send(
      new CreateAccessPointForObjectLambdaCommand({
        AccountId: await account(),
        Name,
        Configuration: {
          SupportingAccessPoint: required(form, "supporting", "Supporting access point"),
          CloudWatchMetricsEnabled: text(form, "metrics") === "on",
          AllowedFeatures: form.getAll("features").map(String) as never,
          TransformationConfigurations: [{ Actions: ["GetObject"], ContentTransformation: { AwsLambda: { FunctionArn: required(form, "function", "Lambda function") } } }],
        },
      }),
    );
    redirect(controlHref("object-lambda", { id: Name }));
  }, { revalidate: ["/s3"], fields: { Name: "name", "Configuration.SupportingAccessPoint": "supporting", SupportingAccessPoint: "supporting", FunctionArn: "function", NoSuchAccessPoint: "supporting" } });
}

export async function deleteObjectLambda(name: string) {
  return act(async () => {
    await (await control()).send(new DeleteAccessPointForObjectLambdaCommand({ AccountId: await account(), Name: name }));
    redirect(controlHref("object-lambda"));
  });
}

// --- Multi-Region access points --------------------------------------------------

export async function createMrap(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Name = required(form, "name", "Name");
    const buckets = form.getAll("buckets").map(String).filter(Boolean);
    if (!buckets.length) throw new FieldError("buckets", "Choose at least one bucket", "required");
    await (await control()).send(
      new CreateMultiRegionAccessPointCommand({
        AccountId: await account(),
        ClientToken: crypto.randomUUID(),
        Details: { Name, Regions: buckets.map((Bucket) => ({ Bucket })), PublicAccessBlock: bpaOf(form) },
      }),
    );
    return `Creating ${Name}`;
  }, { revalidate: ["/s3"], fields: { "Details.Name": "name", Name: "name", Regions: "buckets", NoSuchBucket: "buckets" } });
}

export async function deleteMrap(name: string) {
  return act(async () => {
    await (await control()).send(new DeleteMultiRegionAccessPointCommand({ AccountId: await account(), ClientToken: crypto.randomUUID(), Details: { Name: name } }));
    return `Deleting ${name}`;
  }, "/s3");
}

// --- Batch Operations ------------------------------------------------------------

export async function createJob(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const source = required(form, "source", "Source bucket");
    const op = text(form, "operation");
    let Operation: JobOperation;
    if (op === "tag") {
      const TagSet = tagLines(required(form, "tags", "Tags"));
      Operation = { S3PutObjectTagging: { TagSet } };
    } else if (op === "untag") Operation = { S3DeleteObjectTagging: {} };
    else if (op === "copy") Operation = { S3PutObjectCopy: { TargetResource: `arn:aws:s3:::${required(form, "target", "Destination bucket")}`, TargetKeyPrefix: text(form, "targetPrefix") || undefined } };
    else if (op === "lambda") Operation = { LambdaInvoke: { FunctionArn: required(form, "function", "Lambda function"), InvocationSchemaVersion: "2.0" } };
    else Operation = { S3InitiateRestoreObject: { ExpirationInDays: 1, GlacierJobTier: "STANDARD" } };
    const report = text(form, "report");
    const prefix = text(form, "prefix");
    const out = await (await control()).send(
      new CreateJobCommand({
        AccountId: await account(),
        ClientRequestToken: crypto.randomUUID(),
        Description: text(form, "description") || undefined,
        Priority: Number(text(form, "priority") || 10),
        ConfirmationRequired: text(form, "confirm") === "on",
        RoleArn: await roleFrom(form, "role", BATCH_ROLE),
        Operation,
        ManifestGenerator: {
          S3JobManifestGenerator: {
            SourceBucket: `arn:aws:s3:::${source}`,
            EnableManifestOutput: false,
            Filter: prefix ? { KeyNameConstraint: { MatchAnyPrefix: [prefix] } } : undefined,
          },
        },
        Report: report ? { Enabled: true, Bucket: `arn:aws:s3:::${report}`, Format: "Report_CSV_20180820", ReportScope: "AllTasks", Prefix: "batch-reports" } : { Enabled: false },
      }),
    );
    redirect(controlHref("batch", { id: out.JobId }));
  }, { revalidate: ["/s3"], fields: { Description: "description", Priority: "priority", RoleArn: "role", TargetResource: "target", FunctionArn: "function", TagSet: "tags", SourceBucket: "source", NoSuchBucket: "source" } });
}

export async function setJobStatus(id: string, status: "Ready" | "Cancelled") {
  return act(async () => {
    await (await control()).send(new UpdateJobStatusCommand({ AccountId: await account(), JobId: id, RequestedJobStatus: status, StatusUpdateReason: "MWS console" }));
    return status === "Ready" ? "Job confirmed" : "Job cancelled";
  }, "/s3");
}

export async function setJobPriority(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Priority = Number(required(form, "priority", "Priority"));
    await (await control()).send(new UpdateJobPriorityCommand({ AccountId: await account(), JobId: id, Priority }));
    return `Priority ${Priority}`;
  }, { revalidate: ["/s3"], fields: { Priority: "priority" } });
}

// --- Access Grants ----------------------------------------------------------------

export async function createGrantsInstance() {
  return act(async () => {
    await (await control()).send(new CreateAccessGrantsInstanceCommand({ AccountId: await account() }));
    return "Access Grants instance created";
  }, "/s3");
}

export async function deleteGrantsInstance() {
  return act(async () => {
    await (await control()).send(new DeleteAccessGrantsInstanceCommand({ AccountId: await account() }));
    return "Access Grants instance deleted";
  }, "/s3");
}

export async function createGrantsLocation(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const scope = required(form, "scope", "Location");
    const LocationScope = scope.startsWith("s3://") ? scope : `s3://${scope}`;
    await (await control()).send(new CreateAccessGrantsLocationCommand({ AccountId: await account(), LocationScope, IAMRoleArn: await roleFrom(form, "role", GRANTS_ROLE) }));
    return `Location ${LocationScope} registered`;
  }, { revalidate: ["/s3"], fields: { LocationScope: "scope", IAMRoleArn: "role", InvalidIAMRole: "role" } });
}

export async function deleteGrantsLocation(id: string) {
  return act(async () => {
    await (await control()).send(new DeleteAccessGrantsLocationCommand({ AccountId: await account(), AccessGrantsLocationId: id }));
    return "Location deleted";
  }, "/s3");
}

export async function createGrant(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const sub = text(form, "subprefix");
    await (await control()).send(
      new CreateAccessGrantCommand({
        AccountId: await account(),
        AccessGrantsLocationId: required(form, "location", "Location"),
        AccessGrantsLocationConfiguration: sub ? { S3SubPrefix: sub } : undefined,
        Grantee: { GranteeType: "IAM", GranteeIdentifier: required(form, "grantee", "Grantee") },
        Permission: (text(form, "permission") || "READ") as Permission,
      }),
    );
    return "Grant created";
  }, { revalidate: ["/s3"], fields: { AccessGrantsLocationId: "location", "Grantee.GranteeIdentifier": "grantee", GranteeIdentifier: "grantee", S3SubPrefix: "subprefix", Permission: "permission" } });
}

export async function deleteGrant(id: string) {
  return act(async () => {
    await (await control()).send(new DeleteAccessGrantCommand({ AccountId: await account(), AccessGrantId: id }));
    return "Grant deleted";
  }, "/s3");
}

// --- Storage Lens ------------------------------------------------------------------

export async function createLens(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const Id = required(form, "id", "Dashboard name");
    const activity = text(form, "activity") === "on";
    await (await control()).send(
      new PutStorageLensConfigurationCommand({
        AccountId: await account(),
        ConfigId: Id,
        StorageLensConfiguration: {
          Id,
          IsEnabled: true,
          AccountLevel: { ActivityMetrics: { IsEnabled: activity }, BucketLevel: { ActivityMetrics: { IsEnabled: activity } } },
        },
      }),
    );
    redirect(controlHref("storage-lens", { id: Id }));
  }, { revalidate: ["/s3"], fields: { ConfigId: "id", Id: "id" } });
}

export async function deleteLens(id: string) {
  return act(async () => {
    await (await control()).send(new DeleteStorageLensConfigurationCommand({ AccountId: await account(), ConfigId: id }));
    redirect(controlHref("storage-lens"));
  });
}

export async function deleteLensGroup(name: string) {
  return act(async () => {
    await (await control()).send(new DeleteStorageLensGroupCommand({ AccountId: await account(), Name: name }));
    return `Deleted ${name}`;
  }, "/s3");
}
