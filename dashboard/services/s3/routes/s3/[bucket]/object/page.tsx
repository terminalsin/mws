import { GetObjectCommand, GetObjectTaggingCommand, HeadObjectCommand, ListBucketsCommand, ListObjectVersionsCommand, type HeadObjectCommandOutput } from "@aws-sdk/client-s3";
import { ago, bytes, load, shortName, when } from "@mws-dashboard/aws";
import { ActionForm, Asciify, CodeBlock, ErrorNotice, Facts, Field, FileIcon, List, Page, Pill, Section, Sheet, Tags, type Rule } from "@mws-dashboard/ui";
import { Copy, Download, Link2, Pencil, Tag, Trash2, Undo2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import { bucketHref, downloadHref, links, objectHref, s3 } from "../../../../lib/s3";
import { copyObject, deleteObject, editMetadata, presign, restoreVersion, saveObjectTags } from "../../actions";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

type Props = { params: Promise<{ bucket: string }>; searchParams: Promise<{ key?: string; version?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: (await searchParams).key ?? "Object" };
}

const PREVIEW_LIMIT = 256 * 1024;
const isText = (t?: string) => !!t && /^(text\/|application\/(json|xml|javascript|x-yaml|yaml|x-ndjson|csv))/.test(t);
const isImage = (t?: string) => !!t && t.startsWith("image/");
const STORAGE_CLASSES = ["STANDARD", "INTELLIGENT_TIERING", "STANDARD_IA", "ONEZONE_IA", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE", "REDUCED_REDUNDANCY"];
const KEY: Rule = { minLength: 1, maxLength: 1024 };

type Version = { id: string; marker: boolean; latest: boolean; size?: number; modified?: Date; storage?: string };

/** Every version and delete marker of one key (ListObjectVersions lists by
 * prefix, so stop once the listing passes the key). */
async function versionsOf(bucket: string, key: string): Promise<Version[]> {
  const client = await s3();
  const out: Version[] = [];
  let km: string | undefined;
  let vm: string | undefined;
  for (let page = 0; page < 20; page++) {
    const r = await client.send(new ListObjectVersionsCommand({ Bucket: bucket, Prefix: key, KeyMarker: km, VersionIdMarker: vm }));
    for (const v of r.Versions ?? []) if (v.Key === key) out.push({ id: v.VersionId ?? "null", marker: false, latest: !!v.IsLatest, size: v.Size, modified: v.LastModified, storage: v.StorageClass });
    for (const m of r.DeleteMarkers ?? []) if (m.Key === key) out.push({ id: m.VersionId ?? "null", marker: true, latest: !!m.IsLatest, modified: m.LastModified });
    const past = [...(r.Versions ?? []), ...(r.DeleteMarkers ?? [])].some((v) => v.Key! > key);
    if (!r.IsTruncated || past) break;
    km = r.NextKeyMarker;
    vm = r.NextVersionIdMarker;
  }
  return out.sort((a, b) => (b.modified?.getTime() ?? 0) - (a.modified?.getTime() ?? 0));
}

function facts(h: HeadObjectCommandOutput): ([ReactNode, ReactNode] | null | false | undefined | "" | 0)[] {
  const checksum = (["ChecksumCRC32", "ChecksumCRC32C", "ChecksumCRC64NVME", "ChecksumSHA1", "ChecksumSHA256"] as const).find((k) => h[k]);
  return [
    ["Size", bytes(h.ContentLength)],
    ["Type", h.ContentType],
    ["Modified", <span title={h.LastModified?.toISOString()}>{ago(h.LastModified)}</span>],
    ["Storage class", h.StorageClass ?? "STANDARD"],
    h.VersionId && ["Version ID", <code>{h.VersionId}</code>],
    ["Encryption", h.ServerSideEncryption === "AES256" ? "SSE-S3" : h.ServerSideEncryption],
    h.SSEKMSKeyId && ["KMS key", <Link href={links.key(h.SSEKMSKeyId)}>{shortName(h.SSEKMSKeyId)}</Link>],
    h.BucketKeyEnabled && ["Bucket Key", "Enabled"],
    ["ETag", <code>{h.ETag}</code>],
    checksum && [checksum.replace("Checksum", "Checksum "), <code>{h[checksum]}</code>],
    h.CacheControl && ["Cache-Control", <code>{h.CacheControl}</code>],
    h.ContentEncoding && ["Content-Encoding", h.ContentEncoding],
    h.ContentDisposition && ["Content-Disposition", <code>{h.ContentDisposition}</code>],
    h.WebsiteRedirectLocation && ["Website redirect", h.WebsiteRedirectLocation],
    h.Expiration && ["Expiration", h.Expiration],
    h.ReplicationStatus && ["Replication", <Pill tone={h.ReplicationStatus === "FAILED" ? "bad" : h.ReplicationStatus === "PENDING" ? "warn" : "good"}>{h.ReplicationStatus}</Pill>],
    h.Restore && ["Restore", h.Restore],
    h.ArchiveStatus && ["Archive status", h.ArchiveStatus],
    h.ObjectLockMode && ["Object Lock", `${h.ObjectLockMode.toLowerCase()} until ${when(h.ObjectLockRetainUntilDate)}`],
    h.ObjectLockLegalHoldStatus === "ON" && ["Legal hold", <Pill tone="warn">On</Pill>],
    h.PartsCount && ["Parts", h.PartsCount],
    ...Object.entries(h.Metadata ?? {}).map(([k, v]) => [<code>{`x-amz-meta-${k}`}</code>, v] as [ReactNode, ReactNode]),
  ];
}

export default async function S3Object({ params, searchParams }: Props) {
  const bucket = decodeURIComponent((await params).bucket);
  const { key = "", version } = await searchParams;
  const client = await s3();
  const [head, versions, tags] = await Promise.all([
    load(() => client.send(new HeadObjectCommand({ Bucket: bucket, Key: key, VersionId: version, ChecksumMode: "ENABLED" }))),
    load(() => versionsOf(bucket, key)),
    load(() => client.send(new GetObjectTaggingCommand({ Bucket: bucket, Key: key, VersionId: version }))),
  ]);
  const list = versions.ok ? versions.value : [];
  const latest = list.find((v) => v.latest);
  const deleted = !version && latest?.marker;
  const slash = key.lastIndexOf("/");
  const parent = bucketHref(bucket, { prefix: slash >= 0 ? key.slice(0, slash + 1) : "" });
  const name = key.slice(slash + 1);
  const download = downloadHref(bucket, key, version);
  const buckets = await load(async () => ((await client.send(new ListBucketsCommand({}))).Buckets ?? []).map((b) => b.Name!));
  const versioned = list.some((v) => v.id !== "null") || list.length > 1;
  let preview: string | null = null;
  if (head.ok && isText(head.value.ContentType) && (head.value.ContentLength ?? 0) <= PREVIEW_LIMIT) {
    const body = await load(async () => (await client.send(new GetObjectCommand({ Bucket: bucket, Key: key, VersionId: version }))).Body!.transformToString());
    preview = body.ok ? body.value : null;
  }
  const h = head.ok ? head.value : undefined;
  return (
    <Page
      title={name}
      back={{ href: parent, label: bucket }}
      subtitle={`s3://${bucket}/${key}`}
      actions={
        h && (
          <>
            <a className="icon-button primary" href={download} aria-label="Download" title="Download">
              <Download size={16} aria-hidden />
            </a>
            <Sheet title="Share with a presigned URL" label="Presigned URL" icon={<Link2 size={15} aria-hidden />} testId="presign">
              <ActionForm action={presign.bind(null, bucket, key, version ?? null)} submit="Create URL" testId="presign">
                <Field label="Valid for (minutes)" hint="Up to 7 days" rule={{ type: "integer" }}>
                  <input name="minutes" type="number" min="1" max="10080" defaultValue="60" />
                </Field>
              </ActionForm>
            </Sheet>
            <Sheet title="Copy or move" label="Copy or move" icon={<Copy size={15} aria-hidden />} testId="copy-object">
              <ActionForm action={copyObject.bind(null, bucket, key, version ?? null)} submit="Copy" testId="copy-object">
                <div className="form-row">
                  <Field label="Destination bucket" format="bucket" known={buckets.ok ? buckets.value : []}>
                    <ResourcePicker kind="s3-bucket" use="name" name="bucket" required defaultValue={bucket} />
                  </Field>
                  <Field label="Destination key" rule={KEY}>
                    <input name="key" required defaultValue={key} />
                  </Field>
                </div>
                <Field label="Storage class">
                  <select name="storageClass" defaultValue="">
                    <option value="">Same as source</option>
                    {STORAGE_CLASSES.map((c) => (
                      <option key={c}>{c}</option>
                    ))}
                  </select>
                </Field>
                <label className="check">
                  <input type="checkbox" name="move" /> Move (delete the source after copying)
                </label>
              </ActionForm>
            </Sheet>
            {!version && (
              <Sheet title="Edit metadata" label="Edit metadata" icon={<Pencil size={15} aria-hidden />} testId="edit-metadata">
                <ActionForm action={editMetadata.bind(null, bucket, key)} submit="Save" testId="edit-metadata">
                  <div className="form-row">
                    <Field label="Content type">
                      <input name="contentType" defaultValue={h.ContentType} />
                    </Field>
                    <Field label="Storage class">
                      <select name="storageClass" defaultValue={h.StorageClass ?? "STANDARD"}>
                        {STORAGE_CLASSES.map((c) => (
                          <option key={c}>{c}</option>
                        ))}
                      </select>
                    </Field>
                  </div>
                  <div className="form-row">
                    <Field label="Cache-Control">
                      <input name="cacheControl" defaultValue={h.CacheControl} placeholder="max-age=3600" />
                    </Field>
                    <Field label="Content-Encoding">
                      <input name="contentEncoding" defaultValue={h.ContentEncoding} />
                    </Field>
                  </div>
                  <Field label="Content-Disposition">
                    <input name="contentDisposition" defaultValue={h.ContentDisposition} />
                  </Field>
                  <Field label="User metadata" format="pairs" hint="One key=value per line (x-amz-meta-…)">
                    <textarea name="metadata" defaultValue={Object.entries(h.Metadata ?? {}).map(([k, v]) => `${k}=${v}`).join("\n")} />
                  </Field>
                </ActionForm>
              </Sheet>
            )}
            <Sheet title="Object tags" label="Edit tags" icon={<Tag size={15} aria-hidden />} testId="edit-object-tags">
              <ActionForm action={saveObjectTags.bind(null, bucket, key, version ?? null)} submit="Save" testId="edit-object-tags">
                <Field label="One Key=Value per line" format="tags" hint="Up to 10; empty removes every tag">
                  <textarea name="tags" defaultValue={(tags.ok ? (tags.value.TagSet ?? []) : []).map((t) => `${t.Key}=${t.Value}`).join("\n")} />
                </Field>
              </ActionForm>
            </Sheet>
            <ActionForm
              action={deleteObject.bind(null, bucket, key, version ?? null, parent)}
              submit={version ? "Permanently delete this version" : "Delete object"}
              icon={<Trash2 size={16} aria-hidden />}
              tone="danger"
              confirm={version ? `Permanently delete version ${version} of ${key}?` : versioned ? `Add a delete marker to ${key}? Its versions stay.` : `Delete ${key}?`}
              testId="delete-object"
            />
          </>
        )
      }
    >
      {deleted ? (
        <div className="banner" role="status" data-testid="deleted-banner">
          The latest version is a delete marker: GET answers 404. Remove the marker, or restore an earlier version, below.
        </div>
      ) : !head.ok ? (
        <ErrorNotice error={head.error} />
      ) : null}
      {h && (
        <>
          {isImage(h.ContentType) && (
            <Section plain>
              <Asciify className="preview-image" src={`${download}&inline=1`} alt={name} />
            </Section>
          )}
          {preview !== null && (
            <Section plain>
              <CodeBlock value={preview} label="Object preview" />
            </Section>
          )}
          <Section title={version ? `Version ${version}` : undefined}>
            <Facts items={[...facts(h), tags.ok && tags.value.TagSet?.length ? ["Tags", <Tags tags={tags.value.TagSet} />] : null]} />
            {!tags.ok && <ErrorNotice error={`Tags: ${tags.error}`} />}
          </Section>
        </>
      )}
      {!versions.ok ? (
        <ErrorNotice error={versions.error} />
      ) : (
        (list.length > 1 || list.some((v) => v.marker)) && (
          <Section title="Versions" count={list.length} plain>
            <List
              label="Versions"
              rows={list.map((v) => ({
                key: v.id,
                icon: <FileIcon name={key} />,
                title: <code>{v.id}</code>,
                href: v.marker || v.id === version ? undefined : objectHref(bucket, key, v.id),
                meta: (
                  <>
                    {v.marker && <Pill tone="warn">Delete marker</Pill>}
                    {v.latest && <Pill tone="good">latest</Pill>}
                    {v.id === version && <Pill tone="info">shown</Pill>}
                    {v.storage && v.storage !== "STANDARD" && <Pill>{v.storage}</Pill>}
                    {!v.marker && <span>{bytes(v.size)}</span>}
                    <span title={v.modified?.toISOString()}>{ago(v.modified)}</span>
                  </>
                ),
                actions: (
                  <>
                    {!v.marker && (
                      <a className="icon-button" href={downloadHref(bucket, key, v.id)} aria-label={`Download version ${v.id}`} title="Download this version">
                        <Download size={16} aria-hidden />
                      </a>
                    )}
                    {!v.marker && !v.latest && (
                      <ActionForm action={restoreVersion.bind(null, bucket, key, v.id)} submit={`Make version ${v.id} current`} icon={<Undo2 size={15} aria-hidden />} confirm={`Copy version ${v.id} over ${key} as its latest version?`} />
                    )}
                    <ActionForm
                      action={deleteObject.bind(null, bucket, key, v.id, null)}
                      submit={v.marker ? `Remove delete marker ${v.id}` : `Permanently delete version ${v.id}`}
                      icon={<Trash2 size={15} aria-hidden />}
                      tone="danger"
                      confirm={v.marker ? "Remove this delete marker?" : `Permanently delete version ${v.id}?`}
                    />
                  </>
                ),
              }))}
            />
          </Section>
        )
      )}
    </Page>
  );
}
