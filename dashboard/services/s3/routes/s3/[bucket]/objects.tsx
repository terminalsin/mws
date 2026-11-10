import { ListObjectsV2Command, ListObjectVersionsCommand } from "@aws-sdk/client-s3";
import { ago, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, FileIcon, List, More, Pill, type Row } from "@mws-dashboard/ui";
import { Download, History, Trash2 } from "lucide-react";
import Link from "next/link";

import { BUCKET_ICON, bucketHref, downloadHref, objectHref, s3 } from "../../../lib/s3";
import { deleteFolder, deleteObject } from "../actions";

export type ObjectsParams = { prefix?: string; token?: string; versions?: string; km?: string; vm?: string };

/** A page of keys and folders (ListObjectsV2) or of every version and delete
 * marker (ListObjectVersions), 1,000 at a time with a link to the next page. */
export async function listing(bucket: string, p: ObjectsParams) {
  const client = await s3();
  const Prefix = p.prefix || undefined;
  if (p.versions) {
    return load(async () => {
      const out = await client.send(new ListObjectVersionsCommand({ Bucket: bucket, Prefix, Delimiter: "/", MaxKeys: 1000, KeyMarker: p.km, VersionIdMarker: p.vm }));
      return {
        folders: (out.CommonPrefixes ?? []).map((c) => c.Prefix!),
        versions: [
          ...(out.Versions ?? []).map((v) => ({ ...v, marker: false })),
          ...(out.DeleteMarkers ?? []).map((m) => ({ ...m, marker: true, Size: undefined, StorageClass: undefined })),
        ].sort((a, b) => a.Key!.localeCompare(b.Key!) || (b.LastModified?.getTime() ?? 0) - (a.LastModified?.getTime() ?? 0)),
        objects: [],
        next: out.IsTruncated ? { km: out.NextKeyMarker, vm: out.NextVersionIdMarker } : undefined,
      };
    });
  }
  return load(async () => {
    const out = await client.send(new ListObjectsV2Command({ Bucket: bucket, Prefix, Delimiter: "/", MaxKeys: 1000, ContinuationToken: p.token }));
    return {
      folders: (out.CommonPrefixes ?? []).map((c) => c.Prefix!),
      objects: out.Contents ?? [],
      versions: [],
      next: out.IsTruncated && out.NextContinuationToken ? { token: out.NextContinuationToken } : undefined,
    };
  });
}

export type Listing = Awaited<ReturnType<typeof listing>>;

export function Objects({ bucket, params, data, versioned }: { bucket: string; params: ObjectsParams; data: Listing; versioned: boolean }) {
  if (!data.ok) return <ErrorNotice error={data.error} />;
  const prefix = params.prefix ?? "";
  const showVersions = !!params.versions;
  const parts = prefix.split("/").filter(Boolean);
  const { folders, objects, versions, next } = data.value;
  const rows: Row[] = [
    ...folders.map((f) => ({
      key: `d:${f}`,
      icon: <FileIcon name={f} folder />,
      title: f.slice(prefix.length),
      href: bucketHref(bucket, { prefix: f, versions: params.versions }),
      actions: showVersions ? undefined : (
        <ActionForm
          action={deleteFolder.bind(null, bucket, f)}
          submit={`Delete folder ${f}`}
          icon={<Trash2 size={16} aria-hidden />}
          tone="danger"
          confirm={`Delete every object under ${f}?${versioned ? " Versioning keeps their earlier versions behind delete markers." : ""}`}
        />
      ),
    })),
    ...objects
      .filter((o) => o.Key !== prefix)
      .map((o) => ({
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
            <a className="icon-button" href={downloadHref(bucket, o.Key!)} aria-label={`Download ${o.Key}`} title="Download">
              <Download size={16} aria-hidden />
            </a>
            <ActionForm
              action={deleteObject.bind(null, bucket, o.Key!, null, null)}
              submit={`Delete ${o.Key}`}
              icon={<Trash2 size={16} aria-hidden />}
              tone="danger"
              confirm={versioned ? `Add a delete marker to ${o.Key}? Its versions stay (Show versions).` : `Delete ${o.Key}?`}
            />
          </>
        ),
      })),
    ...versions
      .filter((v) => !(v.Key === prefix && !v.marker))
      .map((v) => {
        const id = v.VersionId ?? "null";
        return {
          key: `v:${v.Key}:${id}`,
          icon: <FileIcon name={v.Key!} />,
          title: v.Key!.slice(prefix.length),
          subtitle: <code className="clip">{id}</code>,
          href: v.marker ? objectHref(bucket, v.Key!) : objectHref(bucket, v.Key!, id),
          meta: (
            <>
              {v.marker && <Pill tone="warn">Delete marker</Pill>}
              {v.IsLatest && <Pill tone="good">latest</Pill>}
              {v.StorageClass && v.StorageClass !== "STANDARD" && <Pill>{v.StorageClass}</Pill>}
              {!v.marker && <span>{bytes(v.Size)}</span>}
              <span title={v.LastModified?.toISOString()}>{ago(v.LastModified)}</span>
            </>
          ),
          actions: (
            <>
              {!v.marker && (
                <a className="icon-button" href={downloadHref(bucket, v.Key!, id)} aria-label={`Download ${v.Key} version ${id}`} title="Download this version">
                  <Download size={16} aria-hidden />
                </a>
              )}
              <ActionForm
                action={deleteObject.bind(null, bucket, v.Key!, id, null)}
                submit={v.marker ? `Remove delete marker of ${v.Key}` : `Permanently delete ${v.Key} version ${id}`}
                icon={<Trash2 size={16} aria-hidden />}
                tone="danger"
                confirm={v.marker ? `Remove this delete marker? ${v.Key} reappears if this was its latest version.` : `Permanently delete version ${id} of ${v.Key}?`}
              />
            </>
          ),
        };
      }),
  ];
  const nextHref = next ? bucketHref(bucket, { prefix: params.prefix, versions: params.versions, ...next }) : undefined;
  return (
    <>
      <div className="filter-bar" style={{ justifyContent: "space-between", alignItems: "center" }}>
        {parts.length > 0 ? (
          <nav className="crumbs path" aria-label="Folder">
            <Link href={bucketHref(bucket, { versions: params.versions })}>{bucket}</Link>
            {parts.map((p, i) => (
              <span key={i}>
                {" / "}
                <Link href={bucketHref(bucket, { prefix: parts.slice(0, i + 1).join("/") + "/", versions: params.versions })}>{p}</Link>
              </span>
            ))}
          </nav>
        ) : (
          <span />
        )}
        <Link
          className={showVersions ? "button plain active" : "button plain"}
          href={bucketHref(bucket, { prefix: params.prefix, versions: showVersions ? undefined : "1" })}
          aria-pressed={showVersions}
          data-testid="show-versions"
        >
          <History size={15} aria-hidden /> {showVersions ? "Hide versions" : "Show versions"}
        </Link>
      </div>
      <List label="Objects" empty={<Empty icon={BUCKET_ICON} />} rows={rows} />
      <More shown={rows.length} noun={showVersions ? "versions" : "objects"} href={nextHref} />
    </>
  );
}
