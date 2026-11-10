import { ListDomainsCommand, ListRepositoriesCommand, type RepositorySummary } from "@aws-sdk/client-codeartifact";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet } from "@mws-dashboard/ui";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { Lock, Package, Plus, Trash2 } from "lucide-react";
import { CreateDomain } from "@mws-dashboard/ui/model/codeartifact";
import type { Metadata } from "next";

import { codeartifact, ICONS } from "../../lib/clients";
import { externalIcon } from "../../lib/external";
import { publicUpstreams } from "../../lib/upstreams";
import { domainHref, repoHref } from "../../lib/refs";
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
  const upstream = repos.ok ? await publicUpstreams(repos.value) : new Map<string, string | undefined>();
  const domainSheet = (
    <Sheet title="Create domain" label="Create domain" icon={<Plus size={15} />} testId="create-domain">
      <ActionForm action={createDomain} submit="Create domain" testId="create-domain">
        <Field label="Domain name" rule={DOMAIN} taken={domains.ok ? domains.value.map((d) => d.name!) : undefined} unique>
          <input name="name" required autoFocus />
        </Field>
        <MoreFields>
          <Field label="KMS key" rule={CreateDomain.encryptionKey} member="encryptionKey" hint="ARN; aws/codeartifact when empty">
            <input name="key" placeholder="arn:aws:kms:…:key/…" />
          </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
  const repoSheet = domains.ok && (
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
    <Page title={tab === "domains" ? "Domains" : "Repositories"} actions={tab === "domains" ? domainSheet : repoSheet || undefined}>
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
                href: domainHref(d.name!, d.owner),
                subtitle: d.encryptionKey?.includes("alias/aws/") ? undefined : d.encryptionKey?.split("/").pop(),
                meta: (
                  <>
                    {repos.ok && <Pill icon={<Package size={11} />}>{repos.value.filter((r) => r.domainName === d.name).length}</Pill>}
                    <span>{ago(d.createdTime)}</span>
                  </>
                ),
                actions: <ActionForm action={deleteDomain.bind(null, d.name!, "")} submit={`Delete ${d.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete domain ${d.name}?`} />,
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
          row={(r) => {
            const ext = upstream.get(r.arn!);
            return {
              key: r.arn!,
              icon: ext && externalIcon(ext) ? <AwsIcon icon={externalIcon(ext)!} size={22} /> : <Lock size={18} aria-label="No public upstream" />,
              title: r.name,
              subtitle: r.description,
              href: repoHref(r.domainName!, r.name!, r.domainOwner),
              meta: (
                <>
                  <span>{ago(r.createdTime)}</span>
                </>
              ),
            };
          }}
        />
      ) : (
        <ErrorNotice error={repos.error} />
      )}
    </Page>
  );
}
