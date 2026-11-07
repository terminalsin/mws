import { GetObjectCommand, GetObjectTaggingCommand, HeadObjectCommand } from "@aws-sdk/client-s3";
import { bytes, load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, CodeBlock, ErrorNotice, KeyValue, PageHeader, Section } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import type { ReactNode } from "react";

import { folderHref, s3 } from "../../../../lib/s3";
import { deleteObject } from "../../actions";

type Props = { params: Promise<{ bucket: string }>; searchParams: Promise<{ key?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: (await searchParams).key ?? "Object" };
}

const PREVIEW_LIMIT = 256 * 1024;

function previewable(type: string | undefined) {
  return !!type && /^(text\/|application\/(json|xml|javascript|x-yaml|yaml|x-ndjson))/.test(type);
}

export default async function S3Object({ params, searchParams }: Props) {
  const bucket = decodeURIComponent((await params).bucket);
  const key = (await searchParams).key ?? "";
  const client = await s3();
  const head = await load(async () => {
    const [h, tags] = await Promise.all([
      client.send(new HeadObjectCommand({ Bucket: bucket, Key: key })),
      client.send(new GetObjectTaggingCommand({ Bucket: bucket, Key: key })),
    ]);
    return { h, tags };
  });
  const slash = key.lastIndexOf("/");
  const parent = folderHref(bucket, slash >= 0 ? key.slice(0, slash + 1) : "");
  let preview: string | null = null;
  if (head.ok && previewable(head.value.h.ContentType) && (head.value.h.ContentLength ?? 0) <= PREVIEW_LIMIT) {
    const body = await load(async () => (await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }))).Body!.transformToString());
    preview = body.ok ? body.value : null;
  }
  const download = `/storage/api/object?bucket=${encodeURIComponent(bucket)}&key=${encodeURIComponent(key)}`;
  return (
    <>
      <PageHeader
        title={key}
        crumbs={[
          { label: "S3 buckets", href: "/s3" },
          { label: bucket, href: parent },
        ]}
        actions={
          <a className="button primary" href={download}>
            Download
          </a>
        }
      />
      {!head.ok ? (
        <ErrorNotice error={head.error} />
      ) : (
        <>
          <Section title="Object">
            <KeyValue
              items={[
                ["Size", bytes(head.value.h.ContentLength)],
                ["Content type", head.value.h.ContentType],
                ["Last modified", when(head.value.h.LastModified)],
                ["ETag", <code>{head.value.h.ETag}</code>],
                ["Storage class", head.value.h.StorageClass ?? "STANDARD"],
                ["Version", head.value.h.VersionId ?? "—"],
                ["Encryption", head.value.h.ServerSideEncryption ?? "—"],
                ["S3 URI", <code>{`s3://${bucket}/${key}`}</code>],
              ]}
            />
          </Section>
          <Section title="Metadata and tags">
            <KeyValue
              items={[
                ...Object.entries(head.value.h.Metadata ?? {}).map(([k, v]) => [<code>x-amz-meta-{k}</code>, v] as [ReactNode, ReactNode]),
                [
                  "Tags",
                  head.value.tags.TagSet?.length ? (
                    <span className="chips">
                      {head.value.tags.TagSet.map((t) => (
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
          {preview !== null && (
            <Section title="Preview">
              <CodeBlock value={preview} label="Object preview" />
            </Section>
          )}
          <Section title="Delete">
            <ActionForm
              action={deleteObject.bind(null, bucket, key, parent)}
              submit="Delete object"
              tone="danger"
              confirm={`Delete ${key}?`}
              inline
            />
          </Section>
        </>
      )}
    </>
  );
}
