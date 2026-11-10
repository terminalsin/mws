import { GetBucketVersioningCommand } from "@aws-sdk/client-s3";
import { ActionForm, Field, Page, Segments, Sheet, type Rule } from "@mws-dashboard/ui";
import { PutObject } from "@mws-dashboard/ui/model/s3";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { FilePlus, FolderPlus, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";

import { BUCKET_ICON, bucketHref, s3 } from "../../../lib/s3";
import { AccessPointList, CreateAccessPointSheet } from "../access-points";
import { createFolder, deleteBucket, putTextObject, uploadObject } from "../actions";
import { Management } from "./management";
import { Objects, listing, type ObjectsParams } from "./objects";
import { Permissions } from "./permissions";
import { Properties } from "./properties";

// S3 keys are at most 1,024 bytes; the model leaves that to the docs.
const KEY: Rule = { ...PutObject.Key, maxLength: 1024 };
// Folders may nest (a/b), but no segment may be empty.
const FOLDER: Rule = { pattern: "^[^/]+(/[^/]+)*/?$", hint: "No empty segments (//)" };
const CONTENT_TYPE: Rule = { pattern: "^[\\w.+-]+/[\\w.+-]+(\\s*;.*)?$", hint: "Like text/plain" };
const CONTENT_TYPES = [
  "text/plain",
  "text/html",
  "text/css",
  "text/csv",
  "text/markdown",
  "application/json",
  "application/xml",
  "application/javascript",
  "application/x-ndjson",
  "application/yaml",
  "application/octet-stream",
  "image/svg+xml",
];
const STORAGE_CLASSES = ["STANDARD", "INTELLIGENT_TIERING", "STANDARD_IA", "ONEZONE_IA", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE", "REDUCED_REDUNDANCY"];

const TABS = [
  ["objects", "Objects"],
  ["properties", "Properties"],
  ["permissions", "Permissions"],
  ["management", "Management"],
  ["access-points", "Access Points"],
] as const;

type Props = { params: Promise<{ bucket: string }>; searchParams: Promise<ObjectsParams & { tab?: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).bucket) };
}

export default async function Bucket({ params, searchParams }: Props) {
  const bucket = decodeURIComponent((await params).bucket);
  const query = await searchParams;
  const { prefix = "", tab = "objects" } = query;
  const objects = tab === "objects";
  const [data, versioning] = objects
    ? await Promise.all([listing(bucket, query), (await s3()).send(new GetBucketVersioningCommand({ Bucket: bucket })).catch(() => undefined)])
    : [null, undefined];
  // Folders already here, for flagging a name that exists.
  const folders = data?.ok ? data.value.folders.map((p) => p.slice(prefix.length).replace(/\/$/, "")) : [];
  return (
    <Page
      title={bucket}
      icon={BUCKET_ICON}
      back={{ href: "/s3", label: "Buckets" }}
      subtitle={`arn:aws:s3:::${bucket}`}
      actions={
        <>
          {objects && (
            <>
              <Sheet title="Upload" label="Upload" icon={<Upload size={15} aria-hidden />} testId="upload-object">
                <ActionForm action={uploadObject.bind(null, bucket)} submit="Upload" testId="upload-object">
                  <input type="hidden" name="prefix" value={prefix} />
                  <Field label="Files">
                    <input type="file" name="file" multiple required />
                  </Field>
                  <MoreFields>
                    <div className="form-row">
                      <Field label="Key" hint="Single file only; defaults to the file name" rule={{ maxLength: KEY.maxLength }}>
                        <input name="key" placeholder={prefix + "…"} />
                      </Field>
                      <Field label="Storage class">
                        <select name="storageClass" defaultValue="STANDARD">
                          {STORAGE_CLASSES.map((c) => (
                            <option key={c}>{c}</option>
                          ))}
                        </select>
                      </Field>
                    </div>
                  </MoreFields>
                </ActionForm>
              </Sheet>
              <Sheet title="New folder" label="New folder" icon={<FolderPlus size={15} aria-hidden />} testId="create-folder">
                <ActionForm action={createFolder.bind(null, bucket, prefix)} submit="Create" testId="create-folder">
                  <Field label="Name" rule={{ ...FOLDER, maxLength: 1023 - prefix.length }} taken={folders} unique>
                    <input name="name" required />
                  </Field>
                </ActionForm>
              </Sheet>
              <Sheet title="New text object" label="New text object" icon={<FilePlus size={15} aria-hidden />} testId="put-text-object">
                <ActionForm action={putTextObject.bind(null, bucket)} submit="Save" testId="put-text-object">
                  <div className="form-row">
                    <Field label="Key" rule={KEY}>
                      <input name="key" defaultValue={prefix} required />
                    </Field>
                    <Field label="Content type" rule={CONTENT_TYPE} known={CONTENT_TYPES}>
                      <input name="contentType" defaultValue="text/plain" />
                    </Field>
                  </div>
                  <textarea name="body" rows={10} aria-label="Body" />
                </ActionForm>
              </Sheet>
            </>
          )}
          {tab === "access-points" && <CreateAccessPointSheet bucket={bucket} taken={[]} />}
          <Sheet title={`Delete ${bucket}`} label="Delete bucket" icon={<Trash2 size={15} aria-hidden />} testId="delete-bucket">
            <ActionForm action={deleteBucket.bind(null, bucket)} submit="Delete bucket" tone="danger" testId="delete-bucket">
              <label className="check">
                <input type="checkbox" name="empty" /> Delete every object and version first
              </label>
            </ActionForm>
          </Sheet>
        </>
      }
    >
      <Segments items={TABS.map(([id, label]) => ({ label, href: id === "objects" ? bucketHref(bucket) : bucketHref(bucket, { tab: id }), active: tab === id }))} />
      {objects && data ? (
        <Objects bucket={bucket} params={query} data={data} versioned={versioning?.Status === "Enabled" || versioning?.Status === "Suspended"} />
      ) : tab === "properties" ? (
        <Properties bucket={bucket} />
      ) : tab === "permissions" ? (
        <Permissions bucket={bucket} />
      ) : tab === "management" ? (
        <Management bucket={bucket} />
      ) : (
        <AccessPointList bucket={bucket} />
      )}
    </Page>
  );
}
