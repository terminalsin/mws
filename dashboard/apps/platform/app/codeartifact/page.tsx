import { ListDomainsCommand, ListRepositoriesCommand, type RepositorySummary } from "@aws-sdk/client-codeartifact";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet } from "@mws-dashboard/ui";
import { Package, Plus, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { codeartifact, ICONS } from "../../lib/clients";
import { createDomain, createRepository, deleteDomain } from "./actions";

export const metadata: Metadata = { title: "CodeArtifact" };

type Props = { searchParams: Promise<{ tab?: string }> };

/** The public repositories AWS can proxy, by format. */
const EXTERNAL = [
  ["public:npmjs", "npm"],
  ["public:pypi", "PyPI"],
  ["public:maven-central", "Maven Central"],
  ["public:crates-io", "crates.io"],
  ["public:rubygems", "RubyGems"],
  ["public:nuget-org", "NuGet"],
  ["public:google-android", "Google Android"],
  ["public:gradle-plugins", "Gradle plugins"],
];

export default async function CodeArtifact({ searchParams }: Props) {
  const { tab = "repositories" } = await searchParams;
  const client = await codeartifact();
  const [domains, repos] = await Promise.all([
    load(() => collect((nextToken) => client.send(new ListDomainsCommand({ nextToken })), (r) => r.domains, (r) => r.nextToken)),
    load(() => collect((nextToken) => client.send(new ListRepositoriesCommand({ nextToken })), (r) => r.repositories, (r) => r.nextToken)),
  ]);
  const domainSheet = (
    <Sheet title="Create domain" label="Create domain" icon={<Plus size={15} />} testId="create-domain">
      <ActionForm action={createDomain} submit="Create domain" testId="create-domain">
        <Field label="Domain name">
          <input name="name" required autoFocus pattern="[a-z][a-z0-9-]{1,49}" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  const repoSheet = domains.ok && domains.value.length > 0 && (
    <Sheet title="Create repository" label="Create repository" testId="create-repository">
      <ActionForm action={createRepository} submit="Create repository" testId="create-repository">
        <Field label="Repository name">
          <input name="name" required autoFocus />
        </Field>
        <Field label="Domain">
          <select name="domain">
            {domains.value.map((d) => (
              <option key={d.name} value={d.name}>
                {d.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Public upstream">
          <select name="external" defaultValue="">
            <option value="">None</option>
            {EXTERNAL.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
        </Field>
        {repos.ok && repos.value.length > 0 && (
          <Field label="Upstream repository">
            <select name="upstream" defaultValue="">
              <option value="">None</option>
              {repos.value.map((r) => (
                <option key={r.arn} value={r.name}>
                  {r.domainName}/{r.name}
                </option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Description">
          <input name="description" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title={tab === "domains" ? "Domains" : "Repositories"} actions={tab === "domains" ? domainSheet : repoSheet || domainSheet}>
      <Segments
        items={[
          { label: "Repositories", href: "/codeartifact", active: tab !== "domains", count: repos.ok ? repos.value.length : undefined },
          { label: "Domains", href: "/codeartifact?tab=domains", active: tab === "domains", count: domains.ok ? domains.value.length : undefined },
        ]}
      />
      {tab === "domains" ? (
        domains.ok ? (
          <Section plain>
            <List
              label="Domains"
              empty={<Empty icon={ICONS.codeartifact} action={domainSheet} />}
              rows={domains.value.map((d) => ({
                key: d.name!,
                icon: <AwsIcon icon={ICONS.codeartifact} size={22} />,
                title: d.name,
                subtitle: d.encryptionKey?.includes("alias/aws/") ? undefined : d.encryptionKey?.split("/").pop(),
                meta: (
                  <>
                    {repos.ok && <Pill icon={<Package size={11} />}>{repos.value.filter((r) => r.domainName === d.name).length}</Pill>}
                    <span>{ago(d.createdTime)}</span>
                  </>
                ),
                actions: <ActionForm action={deleteDomain.bind(null, d.name!)} submit={`Delete ${d.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete domain ${d.name}?`} />,
              }))}
            />
          </Section>
        ) : (
          <ErrorNotice error={domains.error} />
        )
      ) : repos.ok ? (
        <Curated<RepositorySummary>
          label="Repositories"
          empty={<Empty icon={ICONS.codeartifact} action={repoSheet || domainSheet} />}
          sections={[...new Set(repos.value.map((r) => r.domainName!))].sort().map((d) => ({ id: d, title: d, items: repos.value.filter((r) => r.domainName === d) }))}
          row={(r) => ({
            key: r.arn!,
            icon: <Package size={18} />,
            title: r.name,
            subtitle: r.description,
            href: `/codeartifact/repo?domain=${encodeURIComponent(r.domainName!)}&name=${encodeURIComponent(r.name!)}`,
            meta: (
              <>
                <Pill>{r.domainName}</Pill>
                <span>{ago(r.createdTime)}</span>
              </>
            ),
          })}
        />
      ) : (
        <ErrorNotice error={repos.error} />
      )}
    </Page>
  );
}
