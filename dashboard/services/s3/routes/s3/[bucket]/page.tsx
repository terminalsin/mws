import {
  GetBucketCorsCommand,
  GetBucketEncryptionCommand,
  GetBucketLifecycleConfigurationCommand,
  GetBucketLocationCommand,
  GetBucketPolicyCommand,
  GetBucketTaggingCommand,
  GetBucketVersioningCommand,
  GetBucketWebsiteCommand,
  ListObjectsV2Command,
} from "@aws-sdk/client-s3";
import { ago, bytes, load } from "@mws-dashboard/aws";
import {
  ActionForm,
  CodeBlock,
  Empty,
  ErrorNotice,
  Facts,
  Field,
  FileIcon,
  List,
  Page,
  Pill,
  Section,
  Segments,
  Sheet,
  Status,
  Tags,
  type Rule,
} from "@mws-dashboard/ui";
import { PutObject } from "@mws-dashboard/ui/model/s3";
import { Download, FilePlus, FolderPlus, Pencil, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { BUCKET_ICON, bucketHref, objectHref, s3 } from "../../../lib/s3";
import { createFolder, deleteBucket, deleteObject, putTextObject, savePolicy, saveTags, setVersioning, uploadObject } from "../actions";

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

type Listing = Awaited<ReturnType<typeof listObjects>>;

function listObjects(bucket: string, prefix: string) {
  return load(async () =>
    (await s3()).send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix || undefined, Delimiter: "/", MaxKeys: 1000 })),
  );
}

type Props = { params: Promise<{ bucket: string }>; searchParams: Promise<{ prefix?: string; tab?: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).bucket) };
}

/** A missing configuration is an error in S3 (NoSuchBucketPolicy, ...). */
async function optional<T>(read: () => Promise<T>): Promise<T | null> {
  try {
    return await read();
  } catch (e) {
    if (/^NoSuch|NotFound/.test((e as Error).name ?? "")) return null;
    throw e;
  }
}

const download = (bucket: string, key: string) => `/api/s3/object?bucket=${encodeURIComponent(bucket)}&key=${encodeURIComponent(key)}`;

function Objects({ bucket, prefix, listing }: { bucket: string; prefix: string; listing: Listing }) {
  if (!listing.ok) return <ErrorNotice error={listing.error} />;
  const parts = prefix.split("/").filter(Boolean);
  const folders = (listing.value.CommonPrefixes ?? []).map((p) => p.Prefix!);
  const objects = (listing.value.Contents ?? []).filter((o) => o.Key !== prefix);
  return (
    <>
      {parts.length > 0 && (
        <nav className="crumbs path" aria-label="Folder">
          <Link href={bucketHref(bucket)}>{bucket}</Link>
          {parts.map((p, i) => (
            <span key={i}>
              {" / "}
              <Link href={bucketHref(bucket, { prefix: parts.slice(0, i + 1).join("/") + "/" })}>{p}</Link>
            </span>
          ))}
        </nav>
      )}
      <List
        label="Objects"
        empty={<Empty icon={BUCKET_ICON} />}
        rows={[
          ...folders.map((f) => ({
            key: `d:${f}`,
            icon: <FileIcon name={f} folder />,
            title: f.slice(prefix.length),
            href: bucketHref(bucket, { prefix: f }),
          })),
          ...objects.map((o) => ({
            key: `o:${o.Key}`,
            icon: <FileIcon name={o.Key!} />,
            title: o.Key!.slice(prefix.length),
            href: objectHref(bucket, o.Key!),
            meta: (
              <>
                {o.StorageClass && o.StorageClass !== "STANDARD" && <Pill>{o.StorageClass}</Pill>}
                <span>{bytes(o.Size)}</span>
                <span title={o.LastModified?.toISOString()}>{ago(o.LastModified)}</span>
              </>
            ),
            actions: (
              <>
                <a className="icon-button" href={download(bucket, o.Key!)} aria-label={`Download ${o.Key}`} title="Download">
                  <Download size={16} aria-hidden />
                </a>
                <ActionForm
                  action={deleteObject.bind(null, bucket, o.Key!, null)}
                  submit={`Delete ${o.Key}`}
                  icon={<Trash2 size={16} aria-hidden />}
                  tone="danger"
                  confirm={`Delete ${o.Key}?`}
                />
              </>
            ),
          })),
        ]}
      />
      {listing.value.IsTruncated && <p className="muted">First 1,000 keys</p>}
    </>
  );
}

async function Properties({ bucket }: { bucket: string }) {
  const client = await s3();
  const props = await load(async () => {
    const [location, versioning, encryption, policy, tags, website, lifecycle, cors] = await Promise.all([
      client.send(new GetBucketLocationCommand({ Bucket: bucket })),
      client.send(new GetBucketVersioningCommand({ Bucket: bucket })),
      optional(() => client.send(new GetBucketEncryptionCommand({ Bucket: bucket }))),
      optional(() => client.send(new GetBucketPolicyCommand({ Bucket: bucket }))),
      optional(() => client.send(new GetBucketTaggingCommand({ Bucket: bucket }))),
      optional(() => client.send(new GetBucketWebsiteCommand({ Bucket: bucket }))),
      optional(() => client.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket }))),
      optional(() => client.send(new GetBucketCorsCommand({ Bucket: bucket }))),
    ]);
    return { location, versioning, encryption, policy, tags, website, lifecycle, cors };
  });
  if (!props.ok) return <ErrorNotice error={props.error} />;
  const { location, versioning, encryption, policy, tags, website, lifecycle, cors } = props.value;
  const rule = encryption?.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault;
  const versioned = versioning.Status === "Enabled";
  return (
    <>
      <Section
        title="Bucket"
        actions={
          <ActionForm
            action={setVersioning.bind(null, bucket, !versioned)}
            submit={versioned ? "Suspend versioning" : "Enable versioning"}
            tone="plain"
            inline
          />
        }
      >
        <Facts
          items={[
            ["Region", location.LocationConstraint || "us-east-1"],
            ["Versioning", <Status tone={versioned ? "good" : "neutral"}>{versioning.Status ?? "Off"}</Status>],
            ["Encryption", rule ? `${rule.SSEAlgorithm}${rule.KMSMasterKeyID ? ` · ${rule.KMSMasterKeyID}` : ""}` : "None"],
            website && ["Website", website.IndexDocument?.Suffix ?? "redirect"],
            lifecycle?.Rules?.length ? ["Lifecycle rules", lifecycle.Rules.length] : null,
            cors?.CORSRules?.length ? ["CORS rules", cors.CORSRules.length] : null,
          ]}
        />
      </Section>
      <Section
        title="Tags"
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Pencil size={15} aria-hidden />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, bucket)} submit="Save" testId="edit-tags">
              <Field label="One Key=Value per line" format="tags">
                <textarea name="tags" defaultValue={(tags?.TagSet ?? []).map((t) => `${t.Key}=${t.Value}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {tags?.TagSet?.length ? <Tags tags={tags.TagSet} /> : <span className="muted">None</span>}
      </Section>
      <Section
        title="Bucket policy"
        actions={
          <Sheet title="Bucket policy" label="Edit policy" icon={<Pencil size={15} aria-hidden />} testId="edit-policy">
            <ActionForm action={savePolicy.bind(null, bucket)} submit="Save" testId="edit-policy">
              <Field label="Policy JSON" hint="Empty removes the policy" format="policy">
                <textarea name="policy" rows={14} defaultValue={policy?.Policy ? JSON.stringify(JSON.parse(policy.Policy), null, 2) : ""} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {policy?.Policy ? <CodeBlock value={policy.Policy} label="Bucket policy" /> : <span className="muted">None</span>}
      </Section>
      {lifecycle?.Rules?.length ? (
        <Section title="Lifecycle">
          <CodeBlock value={JSON.stringify(lifecycle.Rules)} />
        </Section>
      ) : null}
    </>
  );
}

export default async function Bucket({ params, searchParams }: Props) {
  const bucket = decodeURIComponent((await params).bucket);
  const { prefix = "", tab = "objects" } = await searchParams;
  const base = bucketHref(bucket);
  const listing = tab === "properties" ? null : await listObjects(bucket, prefix);
  // Folders already here, for flagging a name that exists.
  const folders = listing?.ok ? (listing.value.CommonPrefixes ?? []).map((p) => p.Prefix!.slice(prefix.length).replace(/\/$/, "")) : [];
  return (
    <Page
      title={bucket}
      icon={BUCKET_ICON}
      back={{ href: "/s3", label: "Buckets" }}
      actions={
        <>
          {tab !== "properties" && (
            <>
              <Sheet title="Upload" label="Upload" icon={<Upload size={15} aria-hidden />} testId="upload-object">
                <ActionForm action={uploadObject.bind(null, bucket)} submit="Upload" testId="upload-object">
                  <input type="hidden" name="prefix" value={prefix} />
                  <Field label="Files">
                    <input type="file" name="file" multiple required />
                  </Field>
                  <Field label="Key" hint="Single file only; defaults to the file name" rule={{ maxLength: KEY.maxLength }}>
                    <input name="key" placeholder={prefix + "…"} />
                  </Field>
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
      <Segments
        items={[
          { label: "Objects", href: base, active: tab !== "properties" },
          { label: "Properties", href: bucketHref(bucket, { tab: "properties" }), active: tab === "properties" },
        ]}
      />
      {tab === "properties" ? <Properties bucket={bucket} /> : <Objects bucket={bucket} prefix={prefix} listing={listing!} />}
    </Page>
  );
}
