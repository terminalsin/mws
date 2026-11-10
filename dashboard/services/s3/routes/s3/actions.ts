"use server";

import {
  CreateBucketCommand,
  DeleteBucketCommand,
  DeleteBucketPolicyCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  GetObjectCommand,
  ListObjectVersionsCommand,
  PutBucketPolicyCommand,
  PutBucketTaggingCommand,
  PutBucketVersioningCommand,
  PutObjectCommand,
  type BucketLocationConstraint,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { act, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { s3 } from "../../lib/s3";

const bucketPage = (bucket: string) => `/s3/${encodeURIComponent(bucket)}`;

export async function createBucket(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Bucket name");
    const r = await region();
    const client = await s3();
    await client.send(
      new CreateBucketCommand({
        Bucket: name,
        ...(r === "us-east-1" ? {} : { CreateBucketConfiguration: { LocationConstraint: r as BucketLocationConstraint } }),
      }),
    );
    if (text(form, "versioning") === "on") {
      await client.send(new PutBucketVersioningCommand({ Bucket: name, VersioningConfiguration: { Status: "Enabled" } }));
    }
    return `Created ${name}`;
  }, "/s3");
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
        if (objects.length) await client.send(new DeleteObjectsCommand({ Bucket: bucket, Delete: { Objects: objects } }));
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
    if (files.length === 0) throw new Error("Choose a file");
    const prefix = text(form, "prefix");
    const client = await s3();
    for (const file of files) {
      const key = files.length === 1 && text(form, "key") ? text(form, "key") : prefix + file.name;
      await client.send(
        new PutObjectCommand({ Bucket: bucket, Key: key, Body: new Uint8Array(await file.arrayBuffer()), ContentType: file.type || "application/octet-stream" }),
      );
    }
    return files.length === 1 ? `Uploaded ${files[0].name}` : `Uploaded ${files.length} files`;
  }, bucketPage(bucket));
}

export async function putTextObject(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const key = required(form, "key", "Key");
    await (await s3()).send(
      new PutObjectCommand({ Bucket: bucket, Key: key, Body: text(form, "body"), ContentType: text(form, "contentType") || "text/plain" }),
    );
    return `Wrote ${key}`;
  }, bucketPage(bucket));
}

export async function createFolder(bucket: string, prefix: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Folder name").replace(/\/+$/, "");
    await (await s3()).send(new PutObjectCommand({ Bucket: bucket, Key: `${prefix}${name}/`, Body: "" }));
    return `Created ${name}/`;
  }, bucketPage(bucket));
}

export async function deleteObject(bucket: string, key: string, back: string | null) {
  return act(async () => {
    await (await s3()).send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    if (back !== null) redirect(back);
    return `Deleted ${key}`;
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
    JSON.parse(policy);
    await client.send(new PutBucketPolicyCommand({ Bucket: bucket, Policy: policy }));
    return "Policy saved";
  }, bucketPage(bucket));
}

export async function saveTags(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const TagSet = text(form, "tags")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [Key, ...rest] = l.split("=");
        return { Key: Key.trim(), Value: rest.join("=").trim() };
      });
    await (await s3()).send(new PutBucketTaggingCommand({ Bucket: bucket, Tagging: { TagSet } }));
    return "Tags saved";
  }, bucketPage(bucket));
}

/** A presigned GET URL, as the console's "Share" does. */
export async function presign(bucket: string, key: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const minutes = Number(text(form, "minutes") || "60");
    const url = await getSignedUrl(await s3(), new GetObjectCommand({ Bucket: bucket, Key: key }), { expiresIn: Math.round(minutes * 60) });
    return { ok: true, message: `Valid for ${minutes} minutes`, detail: url };
  });
}

