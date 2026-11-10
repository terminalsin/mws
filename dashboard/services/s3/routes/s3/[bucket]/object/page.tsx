import { GetObjectCommand, GetObjectTaggingCommand, HeadObjectCommand, ListObjectVersionsCommand } from "@aws-sdk/client-s3";
import { ago, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, Asciify, CodeBlock, ErrorNotice, Facts, Field, FileIcon, List, Page, Pill, Section, Sheet, Tags } from "@mws-dashboard/ui";
import { Download, Link2, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import type { ReactNode } from "react";

import { bucketHref, s3 } from "../../../../lib/s3";
import { deleteObject, presign } from "../../actions";

type Props = { params: Promise<{ bucket: string }>; searchParams: Promise<{ key?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  return { title: (await searchParams).key ?? "Object" };
}

const PREVIEW_LIMIT = 256 * 1024;
const isText = (t?: string) => !!t && /^(text\/|application\/(json|xml|javascript|x-yaml|yaml|x-ndjson|csv))/.test(t);
const isImage = (t?: string) => !!t && t.startsWith("image/");

export default async function S3Object({ params, searchParams }: Props) {
  const bucket = decodeURIComponent((await params).bucket);
  const key = (await searchParams).key ?? "";
  const client = await s3();
  const head = await load(async () => {
    const [h, tags, versions] = await Promise.all([
      client.send(new HeadObjectCommand({ Bucket: bucket, Key: key })),
      client.send(new GetObjectTaggingCommand({ Bucket: bucket, Key: key })),
      client.send(new ListObjectVersionsCommand({ Bucket: bucket, Prefix: key, MaxKeys: 50 })),
    ]);
    return { h, tags, versions: (versions.Versions ?? []).filter((v) => v.Key === key && v.VersionId && v.VersionId !== "null") };
  });
  const slash = key.lastIndexOf("/");
  const parent = bucketHref(bucket, { prefix: slash >= 0 ? key.slice(0, slash + 1) : "" });
  const name = key.slice(slash + 1);
  const download = `/api/s3/object?bucket=${encodeURIComponent(bucket)}&key=${encodeURIComponent(key)}`;
  let preview: string | null = null;
  if (head.ok && isText(head.value.h.ContentType) && (head.value.h.ContentLength ?? 0) <= PREVIEW_LIMIT) {
    const body = await load(async () => (await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }))).Body!.transformToString());
    preview = body.ok ? body.value : null;
  }
  return (
    <Page
      title={name}
      back={{ href: parent, label: bucket }}
      subtitle={`s3://${bucket}/${key}`}
      actions={
        <>
          <a className="icon-button primary" href={download} aria-label="Download" title="Download">
            <Download size={16} aria-hidden />
          </a>
          <Sheet title="Share with a presigned URL" label="Presigned URL" icon={<Link2 size={15} aria-hidden />} testId="presign">
            <ActionForm action={presign.bind(null, bucket, key)} submit="Create URL" testId="presign">
              <Field label="Valid for (minutes)" hint="Up to 7 days" rule={{ type: "integer" }}>
                <input name="minutes" type="number" min="1" max="10080" defaultValue="60" />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={deleteObject.bind(null, bucket, key, parent)}
            submit="Delete object"
            icon={<Trash2 size={16} aria-hidden />}
            tone="danger"
            confirm={`Delete ${key}?`}
          />
        </>
      }
    >
      {!head.ok ? (
        <ErrorNotice error={head.error} />
      ) : (
        <>
          {isImage(head.value.h.ContentType) && (
            <Section plain>
              <Asciify className="preview-image" src={`${download}&inline=1`} alt={name} />
            </Section>
          )}
          {preview !== null && (
            <Section plain>
              <CodeBlock value={preview} label="Object preview" />
            </Section>
          )}
          <Section>
            <Facts
              items={[
                ["Size", bytes(head.value.h.ContentLength)],
                ["Type", head.value.h.ContentType],
                ["Modified", ago(head.value.h.LastModified)],
                ["Storage class", head.value.h.StorageClass ?? "STANDARD"],
                ["Encryption", head.value.h.ServerSideEncryption],
                ["ETag", <code>{head.value.h.ETag}</code>],
                ...Object.entries(head.value.h.Metadata ?? {}).map(([k, v]) => [<code>{k}</code>, v] as [ReactNode, ReactNode]),
                head.value.tags.TagSet?.length ? ["Tags", <Tags tags={head.value.tags.TagSet} />] : null,
              ]}
            />
          </Section>
          {head.value.versions.length > 1 && (
            <Section title="Versions" count={head.value.versions.length} plain>
              <List
                label="Versions"
                rows={head.value.versions.map((v) => ({
                  key: v.VersionId!,
                  icon: <FileIcon name={key} />,
                  title: <code>{v.VersionId}</code>,
                  meta: (
                    <>
                      {v.IsLatest && <Pill tone="good">latest</Pill>}
                      <span>{bytes(v.Size)}</span>
                      <span>{ago(v.LastModified)}</span>
                    </>
                  ),
                }))}
              />
            </Section>
          )}
        </>
      )}
    </Page>
  );
}
