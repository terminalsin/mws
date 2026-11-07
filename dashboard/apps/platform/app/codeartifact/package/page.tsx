import { ListPackageVersionsCommand, type PackageFormat } from "@aws-sdk/client-codeartifact";
import { collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Section, Status } from "@mws-dashboard/ui";
import { Archive, Eye, EyeOff, Globe, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { codeartifact, FORMAT_ICONS } from "../../../lib/clients";
import { deleteVersion, setVersionStatus } from "../actions";

export const metadata: Metadata = { title: "Package" };

type Props = { searchParams: Promise<{ domain?: string; repo?: string; format?: string; namespace?: string; package?: string }> };

const STATUS_TONE = { Published: "good", Unlisted: "neutral", Archived: "neutral", Disposed: "bad", Deleted: "bad", Unfinished: "warn" } as Record<string, "good" | "neutral" | "bad" | "warn">;

export default async function PackagePage({ searchParams }: Props) {
  const { domain = "", repo = "", format = "npm", namespace, package: pkg = "" } = await searchParams;
  const ref = { domain, repository: repo, format, namespace, package: pkg };
  const back = { href: `/codeartifact/repo?domain=${encodeURIComponent(domain)}&name=${encodeURIComponent(repo)}`, label: repo };
  const versions = await load(async () => {
    const client = await codeartifact();
    return collect(
      (nextToken) => client.send(new ListPackageVersionsCommand({ domain, repository: repo, format: format as PackageFormat, namespace, package: pkg, nextToken })),
      (r) => r.versions,
      (r) => r.nextToken,
    );
  });
  const title = namespace ? `${format === "npm" ? "@" : ""}${namespace}${format === "npm" ? "/" : ":"}${pkg}` : pkg;
  return (
    <Page title={title} back={back} icon={FORMAT_ICONS[format]}>
      {versions.ok ? (
        <Section title="Versions" count={versions.value.length} plain>
          <List
            label="Versions"
            empty={<Empty icon={FORMAT_ICONS[format]} />}
            rows={versions.value.map((v) => ({
              key: v.version!,
              icon: <AwsIcon icon={FORMAT_ICONS[format] ?? FORMAT_ICONS.generic} size={18} />,
              title: v.version,
              meta: (
                <>
                  {v.origin?.originType === "EXTERNAL" && <Globe size={13} aria-label="From a public repository" />}
                  <Status tone={STATUS_TONE[v.status ?? ""] ?? "neutral"}>{v.status?.toLowerCase()}</Status>
                </>
              ),
              actions: (
                <>
                  {v.status === "Published" && <ActionForm action={setVersionStatus.bind(null, ref, v.version!, "Unlisted")} submit={`Unlist ${v.version}`} icon={<EyeOff size={15} />} />}
                  {(v.status === "Unlisted" || v.status === "Archived") && <ActionForm action={setVersionStatus.bind(null, ref, v.version!, "Published")} submit={`Publish ${v.version}`} icon={<Eye size={15} />} />}
                  {v.status !== "Archived" && <ActionForm action={setVersionStatus.bind(null, ref, v.version!, "Archived")} submit={`Archive ${v.version}`} icon={<Archive size={15} />} />}
                  <ActionForm action={deleteVersion.bind(null, ref, v.version!)} submit={`Delete ${v.version}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${pkg} ${v.version}?`} />
                </>
              ),
            }))}
          />
        </Section>
      ) : (
        <ErrorNotice error={versions.error} />
      )}
    </Page>
  );
}
