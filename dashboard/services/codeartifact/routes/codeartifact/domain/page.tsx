import {
  DescribeDomainCommand,
  GetDomainPermissionsPolicyCommand,
  ListPackageGroupsCommand,
  ListRepositoriesInDomainCommand,
} from "@aws-sdk/client-codeartifact";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { CreatePackageGroup } from "@mws-dashboard/ui/model/codeartifact";
import { Boxes, HardDrive, KeyRound, Lock, Package, Plus, Trash2, User } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { codeartifact, ICONS } from "../../../lib/clients";
import { externalIcon } from "../../../lib/external";
import { publicUpstreams } from "../../../lib/upstreams";
import { PolicySection } from "../../../lib/policy";
import { domainHref, groupHref, repoHref } from "../../../lib/refs";
import { createPackageGroup, deleteDomain } from "../actions";

export const metadata: Metadata = { title: "Domain" };

// The model writes Java's \p{IsWhitespace}, which JavaScript does not know
// (without the u flag it reads as the letters p, I, s, ...): use \s.
const PATTERN = { ...CreatePackageGroup.packageGroup, pattern: "^[^\\p{C}\\s]+$" };

type Props = { searchParams: Promise<{ name?: string; owner?: string; tab?: string }> };

function bytes(n?: number) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
}

export default async function Domain({ searchParams }: Props) {
  const { name = "", owner, tab = "repositories" } = await searchParams;
  const back = { href: "/codeartifact?tab=domains", label: "Domains" };
  const self = domainHref(name, owner);
  const data = await load(async () => {
    const c = await codeartifact();
    const args = { domain: name, domainOwner: owner };
    const [d, repos, groups, policy] = await Promise.all([
      c.send(new DescribeDomainCommand(args)).then((r) => r.domain!),
      all((nextToken) => c.send(new ListRepositoriesInDomainCommand({ ...args, nextToken })), (r) => r.repositories, (r) => r.nextToken),
      all((nextToken) => c.send(new ListPackageGroupsCommand({ ...args, nextToken })), (r) => r.packageGroups, (r) => r.nextToken),
      c.send(new GetDomainPermissionsPolicyCommand(args)).then((r) => r.policy?.document, () => undefined),
    ]);
    return { d, repos, groups, policy };
  });
  if (!data.ok) {
    return (
      <Page title={name} back={back} icon={ICONS.codeartifact}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { d, repos, groups, policy } = data.value;
  const key = d.encryptionKey;
  const upstream = tab === "repositories" ? await publicUpstreams(repos) : new Map<string, string | undefined>();
  const groupSheet = (
    <Sheet title="Create package group" label="Create package group" icon={<Plus size={15} />} testId="create-package-group">
      <ActionForm action={createPackageGroup.bind(null, name, owner)} submit="Create package group" testId="create-package-group">
        <Field label="Pattern" rule={PATTERN} taken={groups.map((g) => g.pattern!)} hint="/format/namespace/package prefix, e.g. /npm/my-scope/*">
          <input name="pattern" required placeholder="/npm/my-scope/*" autoFocus />
        </Field>
        <Field label="Description" rule={CreatePackageGroup.description}>
          <input name="description" />
        </Field>
        <Field label="Contact" rule={CreatePackageGroup.contactInfo}>
          <input name="contact" placeholder="team@example.com" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page
      title={d.name!}
      icon={ICONS.codeartifact}
      back={back}
      subtitle={d.arn}
      actions={
        <>
          {tab === "groups" && groupSheet}
          <ActionForm
            action={deleteDomain.bind(null, name, "/codeartifact?tab=domains")}
            submit="Delete domain"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete domain ${name}?`}
          />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <AwsIcon icon={ICONS.codeartifact} size={15} />, value: <Status tone={d.status === "Active" ? "good" : "warn"}>{d.status?.toLowerCase() ?? ""}</Status> },
          d.owner && { label: "Owner", icon: <User size={15} />, value: d.owner },
          { label: "Repositories", icon: <Package size={15} />, value: d.repositoryCount ?? repos.length },
          { label: "Assets", icon: <HardDrive size={15} />, value: bytes(d.assetSizeBytes) },
          key && { label: "Key", icon: <KeyRound size={15} />, value: <Link href={`/kms/key?id=${encodeURIComponent(key)}`}>{key.includes("alias/aws/") ? "AWS managed" : key.split("/").pop()}</Link> },
        ]}
      />
      <Segments
        items={[
          { label: "Repositories", href: self, active: tab === "repositories", count: repos.length },
          { label: "Package groups", href: `${self}&tab=groups`, active: tab === "groups", count: groups.length },
          { label: "Domain policy", href: `${self}&tab=policy`, active: tab === "policy" },
        ]}
      />
      {tab === "groups" ? (
        <Section plain>
          <List
            label="Package groups"
            empty={<Empty icon={ICONS.codeartifact} action={groupSheet} />}
            rows={groups
              .sort((a, b) => (a.pattern ?? "").localeCompare(b.pattern ?? ""))
              .map((g) => {
                const r = g.originConfiguration?.restrictions ?? {};
                const blocked = Object.entries(r).filter(([, x]) => x?.effectiveMode === "BLOCK");
                return {
                  key: g.arn ?? g.pattern!,
                  icon: <Boxes size={18} />,
                  title: g.pattern,
                  subtitle: g.description,
                  href: groupHref(name, g.pattern!, owner),
                  meta: (
                    <>
                      {g.parent?.pattern && <Pill>{g.parent.pattern}</Pill>}
                      {blocked.map(([t]) => (
                        <Pill key={t} tone="warn">
                          {t.toLowerCase().replace("_", " ")} blocked
                        </Pill>
                      ))}
                      <span>{ago(g.createdTime)}</span>
                    </>
                  ),
                };
              })}
          />
        </Section>
      ) : tab === "policy" ? (
        <PolicySection kind="domain" domain={name} owner={owner} arn={d.arn} policy={policy} />
      ) : (
        <Section plain>
          <List
            label="Repositories"
            empty={<Empty icon={ICONS.codeartifact} />}
            rows={repos.map((r) => ({
              key: r.arn ?? r.name!,
              icon: externalIcon(upstream.get(r.arn!)) ? <AwsIcon icon={externalIcon(upstream.get(r.arn!))!} size={22} /> : <Lock size={18} aria-label="No public upstream" />,
              title: r.name,
              subtitle: r.description,
              href: repoHref(name, r.name!, owner),
              meta: <span>{ago(r.createdTime)}</span>,
            }))}
          />
        </Section>
      )}
    </Page>
  );
}
