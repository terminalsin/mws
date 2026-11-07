import {
  GetBucketEncryptionCommand,
  GetBucketLocationCommand,
  GetBucketPolicyCommand,
  GetBucketTaggingCommand,
  GetBucketVersioningCommand,
  ListObjectsV2Command,
} from "@aws-sdk/client-s3";
import { bytes, load, when } from "@mws-dashboard/aws";
import {
  ActionForm,
  Badge,
  CodeBlock,
  ErrorNotice,
  Field,
  KeyValue,
  PageHeader,
  Section,
  Table,
  Tabs,
} from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { folderHref, objectHref, s3 } from "../../../lib/s3";
import { deleteBucket, deleteObject, putTextObject, uploadObject } from "../actions";

type Props = { params: Promise<{ bucket: string }>; searchParams: Promise<{ prefix?: string; tab?: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  return { title: decodeURIComponent((await params).bucket) };
}

/** A missing configuration is an error in S3 (NoSuchBucketPolicy, ...); show it as "none". */
async function optional<T>(read: () => Promise<T>): Promise<T | null> {
  try {
    return await read();
  } catch (e) {
    const name = (e as Error).name ?? "";
    if (/^NoSuch|NotFound|ServerSideEncryptionConfigurationNotFoundError/.test(name)) return null;
    throw e;
  }
}

async function Properties({ bucket }: { bucket: string }) {
  const client = await s3();
  const props = await load(async () => {
    const [location, versioning, encryption, policy, tags] = await Promise.all([
      client.send(new GetBucketLocationCommand({ Bucket: bucket })),
      client.send(new GetBucketVersioningCommand({ Bucket: bucket })),
      optional(() => client.send(new GetBucketEncryptionCommand({ Bucket: bucket }))),
      optional(() => client.send(new GetBucketPolicyCommand({ Bucket: bucket }))),
      optional(() => client.send(new GetBucketTaggingCommand({ Bucket: bucket }))),
    ]);
    return { location, versioning, encryption, policy, tags };
  });
  if (!props.ok) return <ErrorNotice error={props.error} />;
  const { location, versioning, encryption, policy, tags } = props.value;
  const rule = encryption?.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault;
  return (
    <>
      <Section title="Properties">
        <KeyValue
          items={[
            ["Region", location.LocationConstraint || "us-east-1"],
            ["Versioning", versioning.Status ?? "Disabled"],
            ["Default encryption", rule ? `${rule.SSEAlgorithm}${rule.KMSMasterKeyID ? ` (${rule.KMSMasterKeyID})` : ""}` : "none"],
            [
              "Tags",
              tags?.TagSet?.length ? (
                <span className="chips">
                  {tags.TagSet.map((t) => (
                    <Badge key={t.Key}>
                      {t.Key}={t.Value}
                    </Badge>
                  ))}
                </span>
              ) : (
                "none"
              ),
            ],
          ]}
        />
      </Section>
      <Section title="Bucket policy">
        {policy?.Policy ? <CodeBlock value={policy.Policy} label="Bucket policy" /> : <p className="muted">No bucket policy.</p>}
      </Section>
      <Section title="Delete bucket">
        <ActionForm
          action={deleteBucket.bind(null, bucket)}
          submit="Delete bucket"
          tone="danger"
          confirm={`Delete bucket ${bucket}?`}
          inline
        >
          <label className="check">
            <input type="checkbox" name="empty" /> Delete every object and version first
          </label>
        </ActionForm>
      </Section>
    </>
  );
}

async function Objects({ bucket, prefix }: { bucket: string; prefix: string }) {
  const listing = await load(async () =>
    (await s3()).send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix || undefined, Delimiter: "/", MaxKeys: 1000 })),
  );
  const parts = prefix.split("/").filter(Boolean);
  return (
    <>
      <Section
        title={
          <span className="crumbs">
            <Link href={folderHref(bucket, "")}>{bucket}</Link>
            {parts.map((p, i) => (
              <span key={i}>
                {" / "}
                <Link href={folderHref(bucket, parts.slice(0, i + 1).join("/") + "/")}>{p}</Link>
              </span>
            ))}
          </span>
        }
      >
        {listing.ok ? (
          <Table
            label="Objects"
            rows={[
              ...(listing.value.CommonPrefixes ?? []).map((p) => ({ kind: "folder" as const, key: p.Prefix! })),
              ...(listing.value.Contents ?? []).map((o) => ({ kind: "object" as const, key: o.Key!, object: o })),
            ]}
            rowKey={(r) => r.kind + r.key}
            empty={prefix ? "This folder is empty." : "This bucket is empty. Upload a file below."}
            columns={[
              {
                header: "Key",
                className: "wrap",
                cell: (r) =>
                  r.kind === "folder" ? (
                    <Link href={folderHref(bucket, r.key)}>📁 {r.key.slice(prefix.length)}</Link>
                  ) : (
                    <Link href={objectHref(bucket, r.key)}>{r.key.slice(prefix.length)}</Link>
                  ),
              },
              { header: "Size", className: "num", cell: (r) => (r.kind === "object" ? bytes(r.object.Size) : "") },
              { header: "Storage class", cell: (r) => (r.kind === "object" ? r.object.StorageClass : "") },
              { header: "Last modified", cell: (r) => (r.kind === "object" ? when(r.object.LastModified) : "") },
              {
                header: "",
                cell: (r) =>
                  r.kind === "object" && (
                    <ActionForm
                      action={deleteObject.bind(null, bucket, r.key, null)}
                      submit="Delete"
                      tone="danger"
                      confirm={`Delete ${r.key}?`}
                      inline
                    />
                  ),
              },
            ]}
          />
        ) : (
          <ErrorNotice error={listing.error} />
        )}
        {listing.ok && listing.value.IsTruncated && <p className="muted">Showing the first 1000 keys.</p>}
      </Section>
      <Section title="Upload">
        <ActionForm action={uploadObject.bind(null, bucket)} submit="Upload" inline testId="upload-object">
          <input type="hidden" name="prefix" value={prefix} />
          <Field label="File">
            <input type="file" name="file" required />
          </Field>
          <Field label="Key" hint={`Defaults to ${prefix || ""}<file name>`}>
            <input name="key" placeholder={prefix + "file name"} />
          </Field>
        </ActionForm>
      </Section>
      <Section title="Write a text object">
        <ActionForm action={putTextObject.bind(null, bucket)} submit="Put object" testId="put-text-object">
          <div className="form-row">
            <Field label="Key">
              <input name="key" defaultValue={prefix} required />
            </Field>
            <Field label="Content type">
              <input name="contentType" defaultValue="text/plain" />
            </Field>
          </div>
          <Field label="Body">
            <textarea name="body" />
          </Field>
        </ActionForm>
      </Section>
    </>
  );
}

export default async function Bucket({ params, searchParams }: Props) {
  const bucket = decodeURIComponent((await params).bucket);
  const { prefix = "", tab = "objects" } = await searchParams;
  const base = `/s3/${encodeURIComponent(bucket)}`;
  return (
    <>
      <PageHeader title={bucket} crumbs={[{ label: "S3 buckets", href: "/s3" }]} />
      <Tabs
        items={[
          { label: "Objects", href: base, active: tab !== "properties" },
          { label: "Properties", href: `${base}?tab=properties`, active: tab === "properties" },
        ]}
      />
      {tab === "properties" ? <Properties bucket={bucket} /> : <Objects bucket={bucket} prefix={prefix} />}
    </>
  );
}
