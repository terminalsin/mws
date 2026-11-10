import {
  BatchGetImageCommand,
  DescribeImageReplicationStatusCommand,
  DescribeImageScanFindingsCommand,
  DescribeImagesCommand,
  ListImageReferrersCommand,
} from "@aws-sdk/client-ecr";
import { ago, all, bytes, load, when } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Facts, List, Page, Pill, Section, Specs, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Archive, ArchiveRestore, Clock, Download, HardDrive, ScanSearch, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import { ICONS, SEVERITY_TONE, ecr, imageHref, repoHref } from "../../../lib/clients";
import { deleteImage, setStorageClass, startScan } from "../actions";

export const metadata: Metadata = { title: "Image" };

type Props = { searchParams: Promise<{ repo?: string; digest?: string }> };

type Manifest = { mediaType?: string; manifests?: { digest: string; mediaType?: string; size?: number; platform?: { os?: string; architecture?: string; variant?: string } }[]; config?: { mediaType?: string; digest?: string }; layers?: { size?: number }[]; subject?: { digest: string } };

export default async function Image({ searchParams }: Props) {
  const { repo = "", digest = "" } = await searchParams;
  const back = { href: repoHref(repo), label: repo };
  const client = await ecr();
  const detail = await load(async () => (await client.send(new DescribeImagesCommand({ repositoryName: repo, imageIds: [{ imageDigest: digest }] }))).imageDetails?.[0]);
  if (!detail.ok || !detail.value) {
    return (
      <Page title={digest.slice(0, 19)} icon={ICONS.image} back={back}>
        <ErrorNotice error={detail.ok ? "Image not found" : detail.error} />
      </Page>
    );
  }
  const i = detail.value;
  const archived = i.imageStatus === "ARCHIVED";
  const [manifest, findings, referrers, replication] = await Promise.all([
    archived
      ? null
      : load(async () => {
          const out = await client.send(new BatchGetImageCommand({ repositoryName: repo, imageIds: [{ imageDigest: digest }], acceptedMediaTypes: [i.imageManifestMediaType ?? "application/vnd.oci.image.manifest.v1+json"] }));
          const m = out.images?.[0];
          if (!m) throw new Error(out.failures?.map((f) => `${f.failureCode}: ${f.failureReason}`).join("; ") || "Manifest not found");
          return { text: m.imageManifest ?? "", mediaType: m.imageManifestMediaType };
        }),
    i.imageScanStatus
      ? load(async () => {
          try {
            const first = await client.send(new DescribeImageScanFindingsCommand({ repositoryName: repo, imageId: { imageDigest: digest } }));
            const found = [...(first.imageScanFindings?.findings ?? [])];
            let nextToken = first.nextToken;
            for (let n = 0; nextToken && n < 50; n++) {
              const more = await client.send(new DescribeImageScanFindingsCommand({ repositoryName: repo, imageId: { imageDigest: digest }, nextToken }));
              found.push(...(more.imageScanFindings?.findings ?? []));
              nextToken = more.nextToken;
            }
            return { ...first, all: found };
          } catch (e) {
            if ((e as Error).name === "ScanNotFoundException") return null;
            throw e;
          }
        })
      : null,
    load(() =>
      all(
        (nextToken) => client.send(new ListImageReferrersCommand({ repositoryName: repo, subjectId: { imageDigest: digest }, nextToken })),
        (r) => r.referrers,
        (r) => r.nextToken,
      ),
    ),
    load(async () => (await client.send(new DescribeImageReplicationStatusCommand({ repositoryName: repo, imageId: { imageDigest: digest } }))).replicationStatuses ?? []),
  ]);
  let parsed: Manifest | null = null;
  if (manifest?.ok) {
    try {
      parsed = JSON.parse(manifest.value.text);
    } catch {
      parsed = null;
    }
  }
  const counts: Record<string, number | undefined> = findings?.ok ? (findings.value?.imageScanFindings?.findingSeverityCounts ?? {}) : {};
  const scanStatus = findings?.ok ? findings.value?.imageScanStatus?.status : i.imageScanStatus?.status;
  const list = findings?.ok ? (findings.value?.all ?? []) : [];
  const title = i.imageTags?.length ? i.imageTags.join(", ") : digest.slice(0, 19);
  return (
    <Page
      title={title}
      icon={ICONS.image}
      back={back}
      subtitle={digest}
      actions={
        <>
          {!archived && <ActionForm action={startScan.bind(null, repo, digest)} submit="Scan" icon={<ScanSearch size={16} aria-hidden />} testId="start-scan" />}
          <ActionForm
            action={setStorageClass.bind(null, repo, digest, !archived)}
            submit={archived ? "Restore from archive" : "Archive"}
            icon={archived ? <ArchiveRestore size={16} aria-hidden /> : <Archive size={16} aria-hidden />}
            confirm={archived ? undefined : "Archive this image? It cannot be pulled until restored."}
            testId="storage-class"
          />
          <ActionForm action={deleteImage.bind(null, repo, digest, repoHref(repo))} submit="Delete image" icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm="Delete this image?" testId="delete-image" />
        </>
      }
    >
      <LiveRefresh when={scanStatus === "IN_PROGRESS" || scanStatus === "PENDING" || i.imageStatus === "ACTIVATING"} />
      <Specs
        items={[
          { label: "Size", icon: <HardDrive size={15} />, value: bytes(i.imageSizeInBytes) },
          { label: "Pushed", icon: <Clock size={15} />, value: ago(i.imagePushedAt) },
          i.lastRecordedPullTime && { label: "Last pulled", icon: <Download size={15} />, value: ago(i.lastRecordedPullTime) },
          archived && { label: "Storage", icon: <Archive size={15} />, value: "Archived" },
        ]}
      />
      <Section title="Details">
        <Facts
          items={[
            ["Repository", <Link href={repoHref(repo)}>{repo}</Link>],
            ["Manifest media type", <code>{i.imageManifestMediaType}</code>],
            i.artifactMediaType && ["Artifact media type", <code>{i.artifactMediaType}</code>],
            i.imageStatus && i.imageStatus !== "ACTIVE" && ["Status", <Status tone={i.imageStatus === "ACTIVATING" ? "info" : "neutral"}>{i.imageStatus}</Status>],
            i.lastArchivedAt && ["Archived", ago(i.lastArchivedAt)],
            i.lastActivatedAt && ["Restored", ago(i.lastActivatedAt)],
            parsed?.subject && ["Refers to", <Link href={imageHref(repo, parsed.subject.digest)}>{parsed.subject.digest.slice(0, 19)}</Link>],
            parsed?.layers && ["Layers", parsed.layers.length],
          ]}
        />
      </Section>
      <Section
        title="Vulnerabilities"
        icon={<ScanSearch size={16} aria-hidden />}
        count={list.length || undefined}
      >
        {!findings ? (
          <span className="muted">Not scanned</span>
        ) : !findings.ok ? (
          <ErrorNotice error={findings.error} />
        ) : (
          <>
            <p>
              <Status tone={scanStatus === "COMPLETE" ? "good" : scanStatus === "FAILED" ? "bad" : "info"}>{scanStatus ?? "Not scanned"}</Status>{" "}
              {findings.value?.imageScanFindings?.imageScanCompletedAt && <span className="muted">{when(findings.value.imageScanFindings.imageScanCompletedAt)}</span>}{" "}
              {Object.entries(counts).map(([s, n]) => (
                <Pill key={s} tone={SEVERITY_TONE[s] ?? "neutral"}>
                  {n} {s.toLowerCase()}
                </Pill>
              ))}
            </p>
            {findings.value?.imageScanStatus?.description && <p className="muted">{findings.value.imageScanStatus.description}</p>}
            {list.length > 0 && (
              <List
                label="Findings"
                rows={list.map((f, n) => ({
                  key: `${f.name}-${n}`,
                  title: f.uri ? <a href={f.uri}>{f.name}</a> : f.name,
                  subtitle: [f.description, ...(f.attributes ?? []).filter((a) => /package_(name|version)/.test(a.key ?? "")).map((a) => a.value)].filter(Boolean).join(" · "),
                  meta: <Pill tone={SEVERITY_TONE[f.severity ?? ""] ?? "neutral"}>{f.severity}</Pill>,
                }))}
              />
            )}
          </>
        )}
      </Section>
      {parsed?.manifests && (
        <Section title="Images in this index" count={parsed.manifests.length} plain>
          <List
            label="Index manifests"
            rows={parsed.manifests.map((m) => ({
              key: m.digest,
              title: m.platform ? [m.platform.os, m.platform.architecture, m.platform.variant].filter(Boolean).join("/") : <span className="muted">attestation</span>,
              subtitle: <code className="clip">{m.digest}</code>,
              href: imageHref(repo, m.digest),
              meta: <span>{bytes(m.size)}</span>,
            }))}
          />
        </Section>
      )}
      {referrers.ok && referrers.value.length > 0 && (
        <Section title="Referrers" count={referrers.value.length} plain>
          <List
            label="Referrers"
            rows={referrers.value.map((r) => ({
              key: r.digest!,
              title: <code>{r.artifactType ?? r.mediaType}</code>,
              subtitle: <code className="clip">{r.digest}</code>,
              href: imageHref(repo, r.digest!),
              meta: <span>{bytes(r.size)}</span>,
            }))}
          />
        </Section>
      )}
      {!referrers.ok && <ErrorNotice error={`Referrers: ${referrers.error}`} />}
      {replication.ok && replication.value.length > 0 && (
        <Section title="Replication">
          <Facts items={replication.value.map((s) => [`${s.region} (${s.registryId})`, <Status tone={s.status === "COMPLETE" ? "good" : s.status === "FAILED" ? "bad" : "info"}>{s.status ?? ""}</Status>] as [string, ReactNode])} />
        </Section>
      )}
      {manifest && (
        <details>
          <summary>Manifest</summary>
          {manifest.ok ? <CodeBlock value={manifest.value.text} label="Image manifest" /> : <ErrorNotice error={manifest.error} />}
        </details>
      )}
    </Page>
  );
}
