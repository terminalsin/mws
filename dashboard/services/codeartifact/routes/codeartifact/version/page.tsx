import {
  DescribePackageVersionCommand,
  GetPackageVersionReadmeCommand,
  ListPackageVersionAssetsCommand,
  ListPackageVersionDependenciesCommand,
  type PackageFormat,
} from "@aws-sdk/client-codeartifact";
import { ago, all, describeError, load, when } from "@mws-dashboard/aws";
import { AwsIcon, CodeBlock, CopyButton, Empty, ErrorNotice, Facts, List, Page, Pill, Section, Specs, Status } from "@mws-dashboard/ui";
import { ArrowUpFromLine, Clock, Download, FileArchive, Globe, Link2, Scale } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { codeartifact, FORMAT_ICONS } from "../../../lib/clients";
import { packageHref, packageTitle, repoHref } from "../../../lib/refs";
import { STATUS_TONE, VersionActions } from "../../../lib/versions";

export const metadata: Metadata = { title: "Package version" };

type Props = { searchParams: Promise<{ domain?: string; owner?: string; repo?: string; format?: string; namespace?: string; package?: string; version?: string }> };

function size(n?: number) {
  if (n == null) return "";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i ? v.toFixed(1) : v} ${u[i]}`;
}

export default async function Version({ searchParams }: Props) {
  const { domain = "", owner, repo = "", format = "npm", namespace, package: pkg = "", version = "" } = await searchParams;
  const ref = { domain, domainOwner: owner, repository: repo, format, namespace, package: pkg };
  const name = packageTitle(format, namespace, pkg);
  const back = { href: packageHref(ref), label: name };
  const data = await load(async () => {
    const c = await codeartifact();
    const args = { domain, domainOwner: owner, repository: repo, format: format as PackageFormat, namespace, package: pkg, packageVersion: version };
    const [v, assets, deps, readme] = await Promise.all([
      c.send(new DescribePackageVersionCommand(args)).then((r) => r.packageVersion!),
      all((nextToken) => c.send(new ListPackageVersionAssetsCommand({ ...args, nextToken })), (r) => r.assets, (r) => r.nextToken).catch((e: unknown) => e as Error),
      all((nextToken) => c.send(new ListPackageVersionDependenciesCommand({ ...args, nextToken })), (r) => r.dependencies, (r) => r.nextToken).catch(() => []),
      c.send(new GetPackageVersionReadmeCommand(args)).then((r) => r.readme, () => undefined),
    ]);
    return { v, assets, deps, readme };
  });
  if (!data.ok) {
    return (
      <Page title={version} back={back} icon={FORMAT_ICONS[format]}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { v, assets, deps, readme } = data.value;
  const entry = v.origin?.domainEntryPoint;
  const download = (asset: string) =>
    `/api/codeartifact/asset?${new URLSearchParams(
      Object.entries({ domain, owner, repo, format, namespace, package: pkg, version, asset }).filter(([, x]) => x) as [string, string][],
    )}`;
  return (
    <Page
      title={`${name} ${v.version}`}
      back={back}
      icon={FORMAT_ICONS[format]}
      subtitle={v.summary}
      actions={<VersionActions pkg={ref} version={version} status={v.status} name={name} back={packageHref(ref)} />}
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={FORMAT_ICONS[format] ?? FORMAT_ICONS.generic} size={15} />, value: <Status tone={STATUS_TONE[v.status ?? ""] ?? "neutral"}>{v.status?.toLowerCase()}</Status> },
          v.publishedTime && { label: "Published", icon: <Clock size={15} />, value: ago(v.publishedTime) },
          entry?.externalConnectionName && { label: "From", icon: <Globe size={15} />, value: entry.externalConnectionName.replace("public:", "") },
          entry?.repositoryName && {
            label: v.origin?.originType === "EXTERNAL" ? "Entered via" : "Published to",
            icon: <ArrowUpFromLine size={15} />,
            value: <Link href={repoHref(domain, entry.repositoryName, owner)}>{entry.repositoryName}</Link>,
          },
          (v.licenses?.length ?? 0) > 0 && { label: "License", icon: <Scale size={15} />, value: v.licenses!.map((l) => l.name).join(", ") },
        ]}
      />
      <Section>
        <Facts
          items={[
            v.displayName && v.displayName !== pkg && ["Display name", v.displayName],
            v.homePage && ["Home page", <a key="h" href={v.homePage}>{v.homePage}</a>],
            v.sourceCodeRepository && ["Source", <a key="s" href={v.sourceCodeRepository}>{v.sourceCodeRepository}</a>],
            v.revision && ["Revision", <code key="r">{v.revision}</code>],
            v.origin?.originType && ["Origin", v.origin.originType.toLowerCase()],
            v.publishedTime && ["Published", when(v.publishedTime)],
          ]}
        />
      </Section>
      {assets instanceof Error ? (
        <ErrorNotice error={describeError(assets)} />
      ) : (
        <Section title="Assets" count={assets.length} plain>
          <List
            label="Assets"
            empty={<Empty icon={FORMAT_ICONS[format]} />}
            rows={assets.map((a) => {
              const sha = a.hashes?.["SHA-256"];
              return {
                key: a.name!,
                icon: <FileArchive size={18} />,
                title: a.name,
                subtitle: sha ? (
                  <span className="inline-icon">
                    <code title="SHA-256">{sha.slice(0, 16)}…</code>
                    <CopyButton value={sha} label="Copy SHA-256" />
                  </span>
                ) : undefined,
                meta: (
                  <>
                    {Object.keys(a.hashes ?? {}).map((h) => (
                      <Pill key={h}>{h}</Pill>
                    ))}
                    <span>{size(a.size)}</span>
                  </>
                ),
                actions: (
                  <a className="icon-button plain" href={download(a.name!)} aria-label={`Download ${a.name}`} title="Download" download>
                    <Download size={15} />
                  </a>
                ),
              };
            })}
          />
        </Section>
      )}
      {deps.length > 0 && (
        <Section title="Dependencies" count={deps.length} plain>
          <List
            label="Dependencies"
            rows={deps.map((d) => ({
              key: `${d.dependencyType}/${d.namespace ?? ""}/${d.package}`,
              icon: <Link2 size={18} />,
              title: packageTitle(format, d.namespace, d.package!),
              href: packageHref({ ...ref, namespace: d.namespace, package: d.package! }),
              meta: (
                <>
                  {d.versionRequirement && <code>{d.versionRequirement}</code>}
                  {d.dependencyType && <Pill>{d.dependencyType}</Pill>}
                </>
              ),
            }))}
          />
        </Section>
      )}
      {readme && (
        <Section title="Readme">
          <CodeBlock value={readme} label="Readme" />
        </Section>
      )}
    </Page>
  );
}
