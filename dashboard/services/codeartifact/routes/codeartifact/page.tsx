import { ListDomainsCommand, ListRepositoriesCommand, type RepositorySummary } from "@aws-sdk/client-codeartifact";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet } from "@mws-dashboard/ui";
import { Package, Plus, Trash2 } from "lucide-react";
import { CreateDomain } from "@mws-dashboard/ui/model/codeartifact";
import type { Metadata } from "next";

import { codeartifact, ICONS } from "../../lib/clients";
import { RepositoryFields } from "../../lib/repository-fields.tsx";
import { createDomain, createRepository, deleteDomain } from "./actions";

export const metadata: Metadata = { title: "CodeArtifact" };

type Props = { searchParams: Promise<{ tab?: string }> };

// Domain names are unique per account and region.
const DOMAIN = { ...CreateDomain.domain, generate: "name" as const };

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
        <Field label="Domain name" rule={DOMAIN} taken={domains.ok ? domains.value.map((d) => d.name!) : undefined} unique>
          <input name="name" required autoFocus />
        </Field>
      </ActionForm>
    </Sheet>
  );
  const repoSheet = domains.ok && domains.value.length > 0 && (
    <Sheet title="Create repository" label="Create repository" testId="create-repository">
      <ActionForm action={createRepository} submit="Create repository" testId="create-repository">
        <RepositoryFields
          domains={domains.value.map((d) => d.name!)}
          repos={repos.ok ? repos.value.map((r) => ({ domain: r.domainName!, name: r.name! })) : []}
        />
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
