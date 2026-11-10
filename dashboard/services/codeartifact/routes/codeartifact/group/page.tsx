import {
  DescribePackageGroupCommand,
  ListAllowedRepositoriesForGroupCommand,
  ListAssociatedPackagesCommand,
  ListRepositoriesInDomainCommand,
  ListSubPackageGroupsCommand,
  type PackageGroupOriginRestrictionType,
} from "@aws-sdk/client-codeartifact";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Specs } from "@mws-dashboard/ui";
import { UpdatePackageGroup } from "@mws-dashboard/ui/model/codeartifact";
import { ArrowUpFromLine, Boxes, Globe, Pencil, ShieldCheck, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { codeartifact, FORMAT_ICONS, ICONS } from "../../../lib/clients";
import { domainHref, groupHref, packageTitle, repoHref } from "../../../lib/refs";
import { deletePackageGroup, setGroupOrigin, updatePackageGroup } from "../actions";

export const metadata: Metadata = { title: "Package group" };

type Props = { searchParams: Promise<{ domain?: string; owner?: string; pattern?: string }> };

const TYPES: [PackageGroupOriginRestrictionType, string, typeof Upload][] = [
  ["PUBLISH", "Publish", Upload],
  ["EXTERNAL_UPSTREAM", "External upstream", Globe],
  ["INTERNAL_UPSTREAM", "Internal upstream", ArrowUpFromLine],
];
const MODES = [
  ["INHERIT", "Inherit"],
  ["ALLOW", "Allow"],
  ["ALLOW_SPECIFIC_REPOSITORIES", "Allow specific repositories"],
  ["BLOCK", "Block"],
];
const modeLabel = (m?: string) => MODES.find(([v]) => v === m)?.[1].toLowerCase() ?? m?.toLowerCase() ?? "";

export default async function Group({ searchParams }: Props) {
  const { domain = "", owner, pattern = "" } = await searchParams;
  const back = { href: `${domainHref(domain, owner)}&tab=groups`, label: domain };
  const data = await load(async () => {
    const c = await codeartifact();
    const args = { domain, domainOwner: owner, packageGroup: pattern };
    const [g, packages, subs, repos, ...allowed] = await Promise.all([
      c.send(new DescribePackageGroupCommand(args)).then((r) => r.packageGroup!),
      all((nextToken) => c.send(new ListAssociatedPackagesCommand({ ...args, nextToken })), (r) => r.packages, (r) => r.nextToken),
      all((nextToken) => c.send(new ListSubPackageGroupsCommand({ ...args, nextToken })), (r) => r.packageGroups, (r) => r.nextToken),
      all((nextToken) => c.send(new ListRepositoriesInDomainCommand({ domain, domainOwner: owner, nextToken })), (r) => r.repositories, (r) => r.nextToken).catch(() => []),
      ...TYPES.map(([t]) =>
        all(
          (nextToken) => c.send(new ListAllowedRepositoriesForGroupCommand({ ...args, originRestrictionType: t, nextToken })),
          (r) => r.allowedRepositories,
          (r) => r.nextToken,
        ),
      ),
    ]);
    return { g, packages, subs, repos, allowed: Object.fromEntries(TYPES.map(([t], i) => [t, allowed[i]])) as Record<string, string[]> };
  });
  if (!data.ok) {
    return (
      <Page title={pattern} back={back} icon={ICONS.codeartifact}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { g, packages, subs, repos, allowed } = data.value;
  const r = g.originConfiguration?.restrictions ?? {};
  const root = !g.parent;
  return (
    <Page
      title={g.pattern!}
      icon={ICONS.codeartifact}
      back={back}
      subtitle={g.arn}
      actions={
        <>
          <Sheet title="Origin controls" label="Edit origin controls" icon={<ShieldCheck size={15} />} testId="group-origin">
            <ActionForm action={setGroupOrigin.bind(null, domain, owner, pattern, allowed)} submit="Save" testId="group-origin">
              {TYPES.map(([t, label]) => (
                <div key={t} className="form-row">
                  <Field label={label}>
                    <select name={`mode_${t}`} defaultValue={r[t]?.mode ?? (root ? "ALLOW" : "INHERIT")}>
                      {MODES.filter(([m]) => !(root && m === "INHERIT")).map(([m, l]) => (
                        <option key={m} value={m}>
                          {l}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Allowed repositories" hint={`One per line; used by "Allow specific repositories"`} known={repos.map((x) => x.name!)}>
                    <textarea name={`allow_${t}`} rows={2} defaultValue={(allowed[t] ?? []).join("\n")} spellCheck={false} />
                  </Field>
                </div>
              ))}
            </ActionForm>
          </Sheet>
          <Sheet title="Edit package group" label="Edit package group" icon={<Pencil size={15} />} testId="edit-package-group">
            <ActionForm action={updatePackageGroup.bind(null, domain, owner, pattern)} submit="Save" testId="edit-package-group">
              <Field label="Description" rule={UpdatePackageGroup.description}>
                <input name="description" defaultValue={g.description} />
              </Field>
              <Field label="Contact" rule={UpdatePackageGroup.contactInfo}>
                <input name="contact" defaultValue={g.contactInfo} />
              </Field>
            </ActionForm>
          </Sheet>
          {!root && (
            <ActionForm action={deletePackageGroup.bind(null, domain, owner, pattern)} submit="Delete package group" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${pattern}?`} />
          )}
        </>
      }
    >
      <Specs
        items={TYPES.map(([t, label, Icon]) => ({
          label,
          icon: <Icon size={15} />,
          value: (
            <span title={r[t]?.inheritedFrom?.pattern ? `Inherited from ${r[t]!.inheritedFrom!.pattern}` : undefined}>
              {modeLabel(r[t]?.effectiveMode ?? r[t]?.mode)}
              {r[t]?.mode === "INHERIT" && r[t]?.inheritedFrom?.pattern && <span className="muted"> (inherited)</span>}
              {(allowed[t]?.length ?? 0) > 0 && ` · ${allowed[t]!.join(", ")}`}
            </span>
          ),
        }))}
      />
      <Section>
        <Facts
          items={[
            g.description && ["Description", g.description],
            g.contactInfo && ["Contact", g.contactInfo],
            g.parent?.pattern && ["Parent", <Link key="p" href={groupHref(domain, g.parent.pattern, owner)}>{g.parent.pattern}</Link>],
            ["Created", ago(g.createdTime)],
          ]}
        />
      </Section>
      {subs.length > 0 && (
        <Section title="Sub groups" count={subs.length} plain>
          <List
            label="Sub groups"
            rows={subs.map((s) => ({ key: s.pattern!, icon: <Boxes size={18} />, title: s.pattern, subtitle: s.description, href: groupHref(domain, s.pattern!, owner) }))}
          />
        </Section>
      )}
      <Section title="Associated packages" count={packages.length} plain>
        <List
          label="Associated packages"
          empty={<Empty icon={ICONS.codeartifact} />}
          rows={packages.map((p) => ({
            key: `${p.format}/${p.namespace ?? ""}/${p.package}`,
            icon: <AwsIcon icon={FORMAT_ICONS[p.format ?? "generic"] ?? FORMAT_ICONS.generic} size={18} />,
            title: packageTitle(p.format ?? "", p.namespace, p.package!),
            meta: (
              <>
                <Pill>{p.format}</Pill>
                {p.associationType && <Pill tone={p.associationType === "STRONG" ? "info" : undefined}>{p.associationType.toLowerCase()}</Pill>}
              </>
            ),
          }))}
        />
      </Section>
      {repos.length > 0 && (allowed.PUBLISH?.length ?? 0) + (allowed.INTERNAL_UPSTREAM?.length ?? 0) > 0 && (
        <Section title="Allowed repositories" plain>
          <List
            label="Allowed repositories"
            rows={TYPES.flatMap(([t, label]) =>
              (allowed[t] ?? []).map((name) => ({ key: `${t}/${name}`, icon: <ArrowUpFromLine size={18} />, title: name, href: repoHref(domain, name, owner), meta: <Pill>{label}</Pill> })),
            )}
          />
        </Section>
      )}
    </Page>
  );
}
