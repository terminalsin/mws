"use server";

import {
  AbortMultipartUploadCommand,
  CopyObjectCommand,
  CreateBucketCommand,
  DeleteBucketCommand,
  DeleteBucketCorsCommand,
  DeleteBucketEncryptionCommand,
  DeleteBucketLifecycleCommand,
  DeleteBucketOwnershipControlsCommand,
  DeleteBucketPolicyCommand,
  DeleteBucketTaggingCommand,
  DeleteBucketWebsiteCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  DeleteObjectTaggingCommand,
  DeletePublicAccessBlockCommand,
  GetBucketLifecycleConfigurationCommand,
  GetBucketNotificationConfigurationCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  ListObjectVersionsCommand,
  PutBucketCorsCommand,
  PutBucketEncryptionCommand,
  PutBucketLifecycleConfigurationCommand,
  PutBucketLoggingCommand,
  PutBucketNotificationConfigurationCommand,
  PutBucketOwnershipControlsCommand,
  PutBucketPolicyCommand,
  PutBucketTaggingCommand,
  PutBucketVersioningCommand,
  PutBucketWebsiteCommand,
  PutObjectCommand,
  PutObjectLockConfigurationCommand,
  PutObjectTaggingCommand,
  PutPublicAccessBlockCommand,
  type BucketLocationConstraint,
  type CORSRule,
  type Event,
  type LifecycleRule,
  type NotificationConfiguration,
  type ObjectIdentifier,
  type ObjectOwnership,
  type ServerSideEncryption,
  type StorageClass,
  type TransitionStorageClass,
  type S3Client,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { act, checkFailures, FieldError, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { objectHref, s3 } from "../../lib/s3";

const bucketPage = (bucket: string) => `/s3/${encodeURIComponent(bucket)}`;
const objectPage = (bucket: string) => `/s3/${encodeURIComponent(bucket)}/object`;
const pages = (bucket: string) => [bucketPage(bucket), objectPage(bucket)];

/** `key=value` lines (or commas) as S3 tags. */
function tagLines(value: string) {
  return value
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [Key, ...rest] = l.split("=");
      return { Key: Key.trim(), Value: rest.join("=").trim() };
    });
}

function json<T>(form: FormData, field: string, label: string): T {
  try {
    return JSON.parse(required(form, field, label)) as T;
  } catch (e) {
    if (e instanceof FieldError) throw e;
    throw new FieldError(field, "Invalid JSON", "format");
  }
}

/** Delete up to 1,000 objects per call; DeleteObjects answers 200 with per-key `Errors`. */
async function deleteMany(client: S3Client, bucket: string, objects: ObjectIdentifier[]) {
  for (let i = 0; i < objects.length; i += 1000) {
    const out = await client.send(new DeleteObjectsCommand({ Bucket: bucket, Delete: { Objects: objects.slice(i, i + 1000), Quiet: true } }));
    checkFailures(out.Errors, (e) => `${e.Key}${e.VersionId ? ` (${e.VersionId})` : ""}: ${e.Code} ${e.Message ?? ""}`.trim());
  }
}

export async function createBucket(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Bucket name");
    const r = await region();
    const client = await s3();
    // us-east-1 answers 200 when you re-create a bucket you own, so check
    // first: the console says it exists rather than "creating" it again.
    const owned = await client.send(new HeadBucketCommand({ Bucket: name })).then(
      () => true,
      () => false,
    );
    if (owned) throw new FieldError("name", "Already exists", "taken");
    const lock = text(form, "lock") === "on";
    await client.send(
      new CreateBucketCommand({
        Bucket: name,
        ObjectLockEnabledForBucket: lock || undefined,
        ObjectOwnership: (text(form, "ownership") || undefined) as ObjectOwnership | undefined,
        ...(r === "us-east-1" ? {} : { CreateBucketConfiguration: { LocationConstraint: r as BucketLocationConstraint } }),
      }),
    );
    if (text(form, "versioning") === "on" && !lock) {
      await client.send(new PutBucketVersioningCommand({ Bucket: name, VersioningConfiguration: { Status: "Enabled" } }));
    }
    return `Created ${name}`;
  }, { revalidate: ["/s3"], fields: { Bucket: "name", InvalidBucketName: "name", ObjectOwnership: "ownership" } });
}

/** Delete a bucket, first deleting every object version in it when asked. */
export async function deleteBucket(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await s3();
    if (text(form, "empty") === "on") {
      let keyMarker: string | undefined;
      let versionIdMarker: string | undefined;
      do {
        const page = await client.send(new ListObjectVersionsCommand({ Bucket: bucket, KeyMarker: keyMarker, VersionIdMarker: versionIdMarker }));
        const objects = [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])].map((v) => ({ Key: v.Key!, VersionId: v.VersionId }));
        if (objects.length) await deleteMany(client, bucket, objects);
        keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
        versionIdMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
      } while (keyMarker);
    }
    await client.send(new DeleteBucketCommand({ Bucket: bucket }));
    redirect("/s3");
  });
}

export async function uploadObject(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const files = form.getAll("file").filter((f): f is File => f instanceof File && f.size >= 0 && f.name !== "");
    if (files.length === 0) throw new FieldError("file", "Choose a file", "required");
    const prefix = text(form, "prefix");
    const storage = (text(form, "storageClass") || undefined) as StorageClass | undefined;
    const client = await s3();
    for (const file of files) {
      const key = files.length === 1 && text(form, "key") ? text(form, "key") : prefix + file.name;
      await client.send(
        new PutObjectCommand({ Bucket: bucket, Key: key, Body: new Uint8Array(await file.arrayBuffer()), ContentType: file.type || "application/octet-stream", StorageClass: storage }),
      );
    }
    return files.length === 1 ? `Uploaded ${files[0].name}` : `Uploaded ${files.length} files`;
  }, { revalidate: [bucketPage(bucket)], fields: { Key: "key", KeyTooLongError: "key", StorageClass: "storageClass", InvalidStorageClass: "storageClass" } });
}

export async function putTextObject(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const key = required(form, "key", "Key");
    await (await s3()).send(
      new PutObjectCommand({ Bucket: bucket, Key: key, Body: text(form, "body"), ContentType: text(form, "contentType") || "text/plain" }),
    );
    return `Wrote ${key}`;
  }, { revalidate: pages(bucket), fields: { Key: "key", KeyTooLongError: "key", ContentType: "contentType" } });
}

export async function createFolder(bucket: string, prefix: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Folder name").replace(/\/+$/, "");
    await (await s3()).send(new PutObjectCommand({ Bucket: bucket, Key: `${prefix}${name}/`, Body: "" }));
    return `Created ${name}/`;
  }, { revalidate: [bucketPage(bucket)], fields: { KeyTooLongError: "name" } });
}

/** Delete an object. Without a version on a versioned bucket S3 only adds a
 * delete marker; with one, that version is gone for good. */
export async function deleteObject(bucket: string, key: string, version: string | null, back: string | null) {
  return act(async () => {
    const out = await (await s3()).send(new DeleteObjectCommand({ Bucket: bucket, Key: key, VersionId: version ?? undefined }));
    if (back !== null) redirect(back);
    if (version) return `Deleted version ${version}`;
    return out.DeleteMarker ? `Added a delete marker to ${key}` : `Deleted ${key}`;
  }, ...pages(bucket));
}

/** Delete every object under a prefix (a "folder"), as the console does. */
export async function deleteFolder(bucket: string, prefix: string) {
  return act(async () => {
    const client = await s3();
    let token: string | undefined;
    let n = 0;
    do {
      const page = await client.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix, ContinuationToken: token }));
      const keys = (page.Contents ?? []).map((o) => ({ Key: o.Key! }));
      if (keys.length) await deleteMany(client, bucket, keys);
      n += keys.length;
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token);
    return `Deleted ${prefix} (${n} object${n === 1 ? "" : "s"})`;
  }, bucketPage(bucket));
}

/** Make an older version the current one again, by copying it over the key. */
export async function restoreVersion(bucket: string, key: string, version: string) {
  return act(async () => {
    await (await s3()).send(new CopyObjectCommand({ Bucket: bucket, Key: key, CopySource: `${bucket}/${encodeURIComponent(key)}?versionId=${encodeURIComponent(version)}` }));
    return `Version ${version} is current again`;
  }, ...pages(bucket));
}

/** Copy (or move) an object to another key or bucket. */
export async function copyObject(bucket: string, key: string, version: string | null, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const target = required(form, "bucket", "Destination bucket");
    const dest = required(form, "key", "Destination key");
    if (target === bucket && dest === key && !version) throw new FieldError("key", "Choose another key", "server");
    const client = await s3();
    await client.send(
      new CopyObjectCommand({
        Bucket: target,
        Key: dest,
        CopySource: `${bucket}/${encodeURIComponent(key)}${version ? `?versionId=${encodeURIComponent(version)}` : ""}`,
        StorageClass: (text(form, "storageClass") || undefined) as StorageClass | undefined,
      }),
    );
    if (text(form, "move") === "on") {
      await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key, VersionId: version ?? undefined }));
      redirect(objectHref(target, dest));
    }
    return `Copied to s3://${target}/${dest}`;
  }, { revalidate: [...pages(bucket), ...pages(text(form, "bucket") || bucket)], fields: { Bucket: "bucket", NoSuchBucket: "bucket", Key: "key", KeyTooLongError: "key", StorageClass: "storageClass", InvalidStorageClass: "storageClass" } });
}

/** Edit content type, caching headers, user metadata and storage class: a
 * copy onto itself with MetadataDirective REPLACE, as the console does. */
export async function editMetadata(bucket: string, key: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await s3();
    const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    const Metadata = Object.fromEntries(tagLines(text(form, "metadata")).map((t) => [t.Key.toLowerCase().replace(/^x-amz-meta-/, ""), t.Value]));
    await client.send(
      new CopyObjectCommand({
        Bucket: bucket,
        Key: key,
        CopySource: `${bucket}/${encodeURIComponent(key)}`,
        MetadataDirective: "REPLACE",
        ContentType: text(form, "contentType") || undefined,
        CacheControl: text(form, "cacheControl") || undefined,
        ContentDisposition: text(form, "contentDisposition") || undefined,
        ContentEncoding: text(form, "contentEncoding") || undefined,
        Metadata,
        StorageClass: (text(form, "storageClass") || head.StorageClass || undefined) as StorageClass | undefined,
        ServerSideEncryption: head.ServerSideEncryption,
        SSEKMSKeyId: head.SSEKMSKeyId,
      }),
    );
    return "Metadata saved";
  }, { revalidate: pages(bucket), fields: { ContentType: "contentType", CacheControl: "cacheControl", Metadata: "metadata", StorageClass: "storageClass", InvalidStorageClass: "storageClass" } });
}

export async function saveObjectTags(bucket: string, key: string, version: string | null, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const TagSet = tagLines(text(form, "tags"));
    const client = await s3();
    if (TagSet.length) await client.send(new PutObjectTaggingCommand({ Bucket: bucket, Key: key, VersionId: version ?? undefined, Tagging: { TagSet } }));
    else await client.send(new DeleteObjectTaggingCommand({ Bucket: bucket, Key: key, VersionId: version ?? undefined }));
    return TagSet.length ? "Tags saved" : "Tags removed";
  }, { revalidate: [objectPage(bucket)], fields: { Tagging: "tags", InvalidTag: "tags", BadRequest: "tags" } });
}

export async function abortUpload(bucket: string, key: string, uploadId: string) {
  return act(async () => {
    await (await s3()).send(new AbortMultipartUploadCommand({ Bucket: bucket, Key: key, UploadId: uploadId }));
    return `Aborted the upload of ${key}`;
  }, bucketPage(bucket));
}

export async function setVersioning(bucket: string, enabled: boolean) {
  return act(async () => {
    await (await s3()).send(new PutBucketVersioningCommand({ Bucket: bucket, VersioningConfiguration: { Status: enabled ? "Enabled" : "Suspended" } }));
    return enabled ? "Versioning enabled" : "Versioning suspended";
  }, bucketPage(bucket));
}

export async function savePolicy(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = text(form, "policy");
    const client = await s3();
    if (!policy) {
      await client.send(new DeleteBucketPolicyCommand({ Bucket: bucket }));
      return "Policy removed";
    }
    try {
      JSON.parse(policy);
    } catch {
      throw new FieldError("policy", "Invalid JSON", "format");
    }
    await client.send(new PutBucketPolicyCommand({ Bucket: bucket, Policy: policy }));
    return "Policy saved";
  }, { revalidate: [bucketPage(bucket)], fields: { Policy: "policy", MalformedPolicy: "policy", AccessDenied: "policy" } });
}

export async function saveTags(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const TagSet = tagLines(text(form, "tags"));
    const client = await s3();
    // An empty tag set is DeleteBucketTagging, not an empty PutBucketTagging.
    if (TagSet.length) await client.send(new PutBucketTaggingCommand({ Bucket: bucket, Tagging: { TagSet } }));
    else await client.send(new DeleteBucketTaggingCommand({ Bucket: bucket }));
    return TagSet.length ? "Tags saved" : "Tags removed";
  }, { revalidate: [bucketPage(bucket)], fields: { Tagging: "tags", InvalidTag: "tags", MalformedXML: "tags" } });
}

export async function saveEncryption(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const algorithm = (text(form, "algorithm") || "AES256") as ServerSideEncryption;
    const kms = algorithm !== "AES256";
    const key = text(form, "kms");
    await (await s3()).send(
      new PutBucketEncryptionCommand({
        Bucket: bucket,
        ServerSideEncryptionConfiguration: {
          Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: algorithm, KMSMasterKeyID: kms && key ? key : undefined }, BucketKeyEnabled: kms ? text(form, "bucketKey") === "on" : undefined }],
        },
      }),
    );
    return "Default encryption saved";
  }, { revalidate: [bucketPage(bucket)], fields: { SSEAlgorithm: "algorithm", KMSMasterKeyID: "kms", "KMS.NotFoundException": "kms", KMSNotFoundException: "kms", InvalidArgument: "kms" } });
}

export async function resetEncryption(bucket: string) {
  return act(async () => {
    await (await s3()).send(new DeleteBucketEncryptionCommand({ Bucket: bucket }));
    return "Default encryption reset to SSE-S3";
  }, bucketPage(bucket));
}

export async function saveLogging(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const target = text(form, "target");
    await (await s3()).send(
      new PutBucketLoggingCommand({
        Bucket: bucket,
        BucketLoggingStatus: target ? { LoggingEnabled: { TargetBucket: target, TargetPrefix: text(form, "prefix") } } : {},
      }),
    );
    return target ? `Logging to ${target}` : "Server access logging off";
  }, { revalidate: [bucketPage(bucket)], fields: { TargetBucket: "target", InvalidTargetBucketForLogging: "target", NoSuchBucket: "target", TargetPrefix: "prefix" } });
}

export async function saveWebsite(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await s3();
    const mode = text(form, "mode");
    if (mode === "off") {
      await client.send(new DeleteBucketWebsiteCommand({ Bucket: bucket }));
      return "Website hosting off";
    }
    const host = text(form, "redirect");
    await client.send(
      new PutBucketWebsiteCommand({
        Bucket: bucket,
        WebsiteConfiguration:
          mode === "redirect"
            ? { RedirectAllRequestsTo: { HostName: required(form, "redirect", "Host name"), Protocol: (text(form, "protocol") || undefined) as "http" | "https" | undefined } }
            : { IndexDocument: { Suffix: required(form, "index", "Index document") }, ErrorDocument: text(form, "error") ? { Key: text(form, "error") } : undefined },
      }),
    );
    return mode === "redirect" ? `Redirecting to ${host}` : "Website hosting on";
  }, { revalidate: [bucketPage(bucket)], fields: { "IndexDocument.Suffix": "index", "ErrorDocument.Key": "error", "RedirectAllRequestsTo.HostName": "redirect", InvalidArgument: "index" } });
}

export async function saveObjectLock(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const mode = text(form, "mode");
    const days = Number(text(form, "days") || 0);
    await (await s3()).send(
      new PutObjectLockConfigurationCommand({
        Bucket: bucket,
        ObjectLockConfiguration: {
          ObjectLockEnabled: "Enabled",
          Rule: mode ? { DefaultRetention: { Mode: mode as "GOVERNANCE" | "COMPLIANCE", Days: days || 1 } } : undefined,
        },
      }),
    );
    return mode ? `Default retention: ${mode.toLowerCase()} for ${days || 1} days` : "Default retention off";
  }, { revalidate: [bucketPage(bucket)], fields: { Mode: "mode", Days: "days", InvalidArgument: "days" } });
}

// --- Permissions -----------------------------------------------------------

const BPA = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"] as const;

export async function savePublicAccessBlock(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const config = Object.fromEntries(BPA.map((k) => [k, text(form, k) === "on"]));
    const client = await s3();
    if (BPA.every((k) => !config[k])) await client.send(new DeletePublicAccessBlockCommand({ Bucket: bucket }));
    else await client.send(new PutPublicAccessBlockCommand({ Bucket: bucket, PublicAccessBlockConfiguration: config }));
    return BPA.every((k) => config[k]) ? "All public access blocked" : "Block Public Access saved";
  }, bucketPage(bucket));
}

export async function saveOwnership(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const value = text(form, "ownership");
    const client = await s3();
    if (!value) await client.send(new DeleteBucketOwnershipControlsCommand({ Bucket: bucket }));
    else await client.send(new PutBucketOwnershipControlsCommand({ Bucket: bucket, OwnershipControls: { Rules: [{ ObjectOwnership: value as ObjectOwnership }] } }));
    return "Object Ownership saved";
  }, { revalidate: [bucketPage(bucket)], fields: { ObjectOwnership: "ownership", InvalidBucketAclWithObjectOwnership: "ownership" } });
}

export async function saveCors(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await s3();
    if (!text(form, "cors")) {
      await client.send(new DeleteBucketCorsCommand({ Bucket: bucket }));
      return "CORS configuration removed";
    }
    const parsed = json<CORSRule[] | { CORSRules: CORSRule[] }>(form, "cors", "CORS rules");
    const CORSRules = Array.isArray(parsed) ? parsed : parsed.CORSRules;
    if (!Array.isArray(CORSRules) || CORSRules.length === 0) throw new FieldError("cors", "A list of CORS rules", "format");
    await client.send(new PutBucketCorsCommand({ Bucket: bucket, CORSConfiguration: { CORSRules } }));
    return "CORS saved";
  }, { revalidate: [bucketPage(bucket)], fields: { CORSConfiguration: "cors", CORSRules: "cors", MalformedXML: "cors", InvalidRequest: "cors" } });
}

// --- Event notifications ------------------------------------------------------

/** Read-modify-write of the whole notification configuration. */
async function editNotifications(bucket: string, change: (c: NotificationConfiguration) => void) {
  const client = await s3();
  const current = await client.send(new GetBucketNotificationConfigurationCommand({ Bucket: bucket }));
  const config: NotificationConfiguration = {
    TopicConfigurations: current.TopicConfigurations ?? [],
    QueueConfigurations: current.QueueConfigurations ?? [],
    LambdaFunctionConfigurations: current.LambdaFunctionConfigurations ?? [],
    ...(current.EventBridgeConfiguration ? { EventBridgeConfiguration: current.EventBridgeConfiguration } : {}),
  };
  change(config);
  await client.send(new PutBucketNotificationConfigurationCommand({ Bucket: bucket, NotificationConfiguration: config }));
}

export async function addNotification(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Id = required(form, "id", "Name");
    const type = text(form, "type");
    const arn = required(form, "arn", "Destination ARN");
    const Events = form.getAll("events").map(String) as Event[];
    if (!Events.length) throw new FieldError("events", "Choose at least one event type", "required");
    const rules = [
      text(form, "prefix") && { Name: "prefix" as const, Value: text(form, "prefix") },
      text(form, "suffix") && { Name: "suffix" as const, Value: text(form, "suffix") },
    ].filter((r): r is { Name: "prefix" | "suffix"; Value: string } => !!r);
    const Filter = rules.length ? { Key: { FilterRules: rules } } : undefined;
    await editNotifications(bucket, (c) => {
      const all = [...c.TopicConfigurations!, ...c.QueueConfigurations!, ...c.LambdaFunctionConfigurations!];
      if (all.some((x) => x.Id === Id)) throw new FieldError("id", "Already exists", "taken");
      if (type === "sns") c.TopicConfigurations!.push({ Id, TopicArn: arn, Events, Filter });
      else if (type === "sqs") c.QueueConfigurations!.push({ Id, QueueArn: arn, Events, Filter });
      else c.LambdaFunctionConfigurations!.push({ Id, LambdaFunctionArn: arn, Events, Filter });
    });
    return `Notification ${Id} added`;
  }, { revalidate: [bucketPage(bucket)], fields: { InvalidArgument: "arn", TopicArn: "arn", QueueArn: "arn", LambdaFunctionArn: "arn" } });
}

export async function deleteNotification(bucket: string, id: string) {
  return act(async () => {
    await editNotifications(bucket, (c) => {
      c.TopicConfigurations = c.TopicConfigurations!.filter((x) => x.Id !== id);
      c.QueueConfigurations = c.QueueConfigurations!.filter((x) => x.Id !== id);
      c.LambdaFunctionConfigurations = c.LambdaFunctionConfigurations!.filter((x) => x.Id !== id);
    });
    return `Notification ${id} deleted`;
  }, bucketPage(bucket));
}

export async function setEventBridge(bucket: string, on: boolean) {
  return act(async () => {
    await editNotifications(bucket, (c) => {
      if (on) c.EventBridgeConfiguration = {};
      else delete c.EventBridgeConfiguration;
    });
    return on ? "Sending events to EventBridge" : "EventBridge off";
  }, bucketPage(bucket));
}

// --- Lifecycle -------------------------------------------------------------

async function lifecycleRules(client: S3Client, bucket: string): Promise<LifecycleRule[]> {
  try {
    return (await client.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket }))).Rules ?? [];
  } catch (e) {
    if ((e as Error).name === "NoSuchLifecycleConfiguration") return [];
    throw e;
  }
}

async function putLifecycle(client: S3Client, bucket: string, Rules: LifecycleRule[]) {
  if (Rules.length) await client.send(new PutBucketLifecycleConfigurationCommand({ Bucket: bucket, LifecycleConfiguration: { Rules } }));
  else await client.send(new DeleteBucketLifecycleCommand({ Bucket: bucket }));
}

const days = (form: FormData, name: string) => {
  const v = text(form, name);
  if (!v) return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) throw new FieldError(name, "A whole number of days, 1 or more", "range", { min: 1, type: "integer" });
  return n;
};

export async function addLifecycleRule(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const ID = required(form, "id", "Rule name");
    const expire = days(form, "expire");
    const transition = days(form, "transition");
    const noncurrent = days(form, "noncurrent");
    const abort = days(form, "abort");
    if (!expire && !transition && !noncurrent && !abort) throw new FieldError("expire", "Choose at least one action", "required");
    const client = await s3();
    const rules = await lifecycleRules(client, bucket);
    if (rules.some((r) => r.ID === ID)) throw new FieldError("id", "Already exists", "taken");
    rules.push({
      ID,
      Status: "Enabled",
      Filter: { Prefix: text(form, "prefix") },
      Expiration: expire ? { Days: expire } : undefined,
      Transitions: transition ? [{ Days: transition, StorageClass: (text(form, "storageClass") || "STANDARD_IA") as TransitionStorageClass }] : undefined,
      NoncurrentVersionExpiration: noncurrent ? { NoncurrentDays: noncurrent } : undefined,
      AbortIncompleteMultipartUpload: abort ? { DaysAfterInitiation: abort } : undefined,
    });
    await putLifecycle(client, bucket, rules);
    return `Rule ${ID} added`;
  }, { revalidate: [bucketPage(bucket)], fields: { InvalidArgument: "expire", InvalidRequest: "transition", MalformedXML: "id" } });
}

export async function setLifecycleRule(bucket: string, id: string, enabled: boolean | null) {
  return act(async () => {
    const client = await s3();
    const rules = await lifecycleRules(client, bucket);
    const next = enabled === null ? rules.filter((r) => r.ID !== id) : rules.map((r) => (r.ID === id ? { ...r, Status: enabled ? ("Enabled" as const) : ("Disabled" as const) } : r));
    await putLifecycle(client, bucket, next);
    return enabled === null ? `Rule ${id} deleted` : enabled ? `Rule ${id} enabled` : `Rule ${id} disabled`;
  }, bucketPage(bucket));
}

export async function saveLifecycleJson(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await s3();
    if (!text(form, "rules")) {
      await client.send(new DeleteBucketLifecycleCommand({ Bucket: bucket }));
      return "Lifecycle configuration removed";
    }
    const parsed = json<LifecycleRule[] | { Rules: LifecycleRule[] }>(form, "rules", "Rules");
    const Rules = Array.isArray(parsed) ? parsed : parsed.Rules;
    if (!Array.isArray(Rules)) throw new FieldError("rules", "A list of lifecycle rules", "format");
    await putLifecycle(client, bucket, Rules);
    return "Lifecycle rules saved";
  }, { revalidate: [bucketPage(bucket)], fields: { LifecycleConfiguration: "rules", Rules: "rules", MalformedXML: "rules", InvalidArgument: "rules", InvalidRequest: "rules" } });
}

/** A presigned GET URL, as the console's "Share" does. */
export async function presign(bucket: string, key: string, version: string | null, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const minutes = Number(text(form, "minutes") || "60");
    const url = await getSignedUrl(await s3(), new GetObjectCommand({ Bucket: bucket, Key: key, VersionId: version ?? undefined }), { expiresIn: Math.round(minutes * 60) });
    return { ok: true, message: `Valid for ${minutes} minutes`, detail: url };
  });
}
