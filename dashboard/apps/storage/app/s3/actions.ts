"use server";

import {
  CreateBucketCommand,
  DeleteBucketCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  ListObjectVersionsCommand,
  PutObjectCommand,
  type BucketLocationConstraint,
} from "@aws-sdk/client-s3";
import { act, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { s3 } from "../../lib/s3";

export async function createBucket(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Bucket name");
    const r = await region();
    await (await s3()).send(
      new CreateBucketCommand({
        Bucket: name,
        ...(r === "us-east-1" ? {} : { CreateBucketConfiguration: { LocationConstraint: r as BucketLocationConstraint } }),
      }),
    );
    return `Created bucket ${name}`;
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
        const page = await client.send(
          new ListObjectVersionsCommand({ Bucket: bucket, KeyMarker: keyMarker, VersionIdMarker: versionIdMarker }),
        );
        const objects = [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])].map((v) => ({
          Key: v.Key!,
          VersionId: v.VersionId,
        }));
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
    const file = form.get("file");
    if (!(file instanceof File) || file.size === 0) throw new Error("Choose a file to upload");
    const prefix = text(form, "prefix");
    const key = text(form, "key") || prefix + file.name;
    await (await s3()).send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: new Uint8Array(await file.arrayBuffer()),
        ContentType: file.type || "application/octet-stream",
      }),
    );
    return `Uploaded ${key}`;
  }, `/s3/${encodeURIComponent(bucket)}`);
}

export async function putTextObject(bucket: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const key = required(form, "key", "Key");
    await (await s3()).send(
      new PutObjectCommand({ Bucket: bucket, Key: key, Body: text(form, "body"), ContentType: text(form, "contentType") || "text/plain" }),
    );
    return `Wrote ${key}`;
  }, `/s3/${encodeURIComponent(bucket)}`);
}

export async function deleteObject(bucket: string, key: string, back: string | null) {
  return act(async () => {
    await (await s3()).send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
    if (back !== null) redirect(back);
    return `Deleted ${key}`;
  }, `/s3/${encodeURIComponent(bucket)}`);
}
