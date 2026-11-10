import {
  DescribePullThroughCacheRulesCommand,
  DescribeRegistryCommand,
  DescribeRepositoryCreationTemplatesCommand,
  GetAccountSettingCommand,
  GetRegistryPolicyCommand,
  GetRegistryScanningConfigurationCommand,
} from "@aws-sdk/client-ecr";
import { DescribeRegistriesCommand, DescribeRepositoriesCommand as DescribePublicRepositoriesCommand } from "@aws-sdk/client-ecr-public";
import { ago, all, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreatePullThroughCacheRule, CreateRepository as CreateRepositoryRules, CreateRepositoryCreationTemplate } from "@mws-dashboard/ui/model/ecr";
import { CreateRepository as CreatePublicRules } from "@mws-dashboard/ui/model/ecr-public";
import { Globe, Lock, Pencil, Plus, ScanSearch, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import { ICONS, ecr, ecrPublic, links, publicHref, repoHref, repositories } from "../../lib/clients";
import {
  createPublicRepository,
  createPullThrough,
  createRepository,
  createTemplate,
  deletePullThrough,
  deleteTemplate,
  saveRegistryPolicy,
  saveReplication,
  saveScanning,
  setAccountSetting,
} from "./actions";

export const metadata: Metadata = { title: "ECR" };

const REPOSITORY_NAME: Rule = { ...CreateRepositoryRules.repositoryName, hint: "Lowercase words joined by . _ - or /", generate: "name" };
const PUBLIC_NAME: Rule = { ...CreatePublicRules.repositoryName, hint: "Lowercase words joined by . _ - or /", generate: "name" };

type Props = { searchParams: Promise<{ tab?: string }> };

function CreateRepository({ names }: { names: string[] }) {
  return (
    <Sheet title="Create repository" label="Create repository" testId="create-repository">
      <ActionForm action={createRepository} submit="Create" testId="create-repository">
        <Field label="Repository name" rule={REPOSITORY_NAME} taken={names} unique>
          <input name="name" required autoFocus placeholder="team/app" />
        </Field>
        <label className="check">
          <input type="checkbox" name="immutable" /> Immutable tags
        </label>
        <label className="check">
          <input type="checkbox" name="scan" defaultChecked /> Scan on push
        </label>
        <div className="form-row">
          <Field label="Encryption">
            <select name="encryption" defaultValue="AES256">
              <option value="AES256">AES-256</option>
              <option value="KMS">AWS KMS</option>
            </select>
          </Field>
          <Field label="KMS key" hint="Empty uses aws/ecr" member="kmsKey">
            <input name="kms" />
          </Field>
        </div>
        <Field label="Keep last N images">
          <input name="keep" type="number" min={0} step={1} placeholder="All" />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

const TABS = [
  ["private", "Private repositories"],
  ["public", "Public repositories"],
  ["registry", "Private registry"],
] as const;

async function Private(): Promise<{ actions: ReactNode; body: ReactNode }> {
  const repos = await load(repositories);
  const names = repos.ok ? repos.value.map((r) => r.repositoryName!) : [];
  return {
    actions: <CreateRepository names={names} />,
    body: repos.ok ? (
      <List
        label="Repositories"
        empty={<Empty icon={ICONS.ecr} action={<CreateRepository names={names} />} />}
        rows={repos.value
          .sort((a, b) => a.repositoryName!.localeCompare(b.repositoryName!))
          .map((r) => ({
            key: r.repositoryArn!,
            icon: <AwsIcon icon={ICONS.repo} size={24} />,
            title: r.repositoryName,
            subtitle: <code className="clip">{r.repositoryUri}</code>,
            href: repoHref(r.repositoryName!),
            meta: (
              <>
                {r.imageTagMutability?.startsWith("IMMUTABLE") && <Lock size={13} aria-label="Immutable tags" />}
                {r.imageScanningConfiguration?.scanOnPush && <ScanSearch size={14} aria-label="Scan on push" />}
                {r.encryptionConfiguration?.encryptionType && r.encryptionConfiguration.encryptionType !== "AES256" && <Pill>{r.encryptionConfiguration.encryptionType}</Pill>}
                <span>{ago(r.createdAt)}</span>
              </>
            ),
          }))}
      />
    ) : (
      <ErrorNotice error={repos.error} />
    ),
  };
}

async function Public(): Promise<{ actions: ReactNode; body: ReactNode }> {
  const data = await load(async () => {
    const client = await ecrPublic();
    const [repos, registries] = await Promise.all([
      all(
        (nextToken) => client.send(new DescribePublicRepositoriesCommand({ nextToken })),
        (r) => r.repositories,
        (r) => r.nextToken,
      ),
      all(
        (nextToken) => client.send(new DescribeRegistriesCommand({ nextToken })),
        (r) => r.registries,
        (r) => r.nextToken,
      ),
    ]);
    return { repos, registries };
  });
  const names = data.ok ? data.value.repos.map((r) => r.repositoryName!) : [];
  const actions = (
    <Sheet title="Create public repository" label="Create public repository" testId="create-public-repository">
      <ActionForm action={createPublicRepository} submit="Create" testId="create-public-repository">
        <Field label="Repository name" rule={PUBLIC_NAME} taken={names} unique>
          <input name="name" required autoFocus />
        </Field>
        <Field label="Description" rule={{ maxLength: 1024 }}>
          <input name="description" />
        </Field>
        <div className="form-row">
          <Field label="Architectures" hint="Like x86-64, ARM 64">
            <input name="architectures" />
          </Field>
          <Field label="Operating systems" hint="Linux, Windows">
            <input name="os" defaultValue="Linux" />
          </Field>
        </div>
        <Field label="About (Markdown)">
          <textarea name="about" rows={3} />
        </Field>
        <Field label="Usage (Markdown)">
          <textarea name="usage" rows={3} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!data.ok) return { actions, body: <ErrorNotice error={data.error} /> };
  const alias = data.value.registries[0]?.aliases?.find((a) => a.primaryRegistryAlias)?.name ?? data.value.registries[0]?.aliases?.[0]?.name;
  return {
    actions,
    body: (
      <>
        {data.value.registries[0] && (
          <Section title="Public registry">
            <Facts items={[["Registry", <code>{data.value.registries[0].registryUri}</code>], alias && ["Default alias", alias], ["Verified", data.value.registries[0].verified ? "Yes" : "No"]]} />
          </Section>
        )}
        <List
          label="Public repositories"
          empty={<Empty icon={ICONS.ecr} action={actions} />}
          rows={data.value.repos.map((r) => ({
            key: r.repositoryArn!,
            icon: <AwsIcon icon={ICONS.repo} size={24} />,
            title: r.repositoryName,
            subtitle: <code className="clip">{r.repositoryUri}</code>,
            href: publicHref(r.repositoryName!),
            meta: (
              <>
                <Globe size={13} aria-label="Public" />
                <span>{ago(r.createdAt)}</span>
              </>
            ),
          }))}
        />
      </>
    ),
  };
}

const SETTINGS = [
  ["BASIC_SCAN_TYPE_VERSION", ["AWS_NATIVE", "CLAIR"]],
  ["REGISTRY_POLICY_SCOPE", ["V1", "V2"]],
  ["BLOB_MOUNTING", ["ENABLED", "DISABLED"]],
] as const;

async function Registry(): Promise<{ actions: ReactNode; body: ReactNode }> {
  const client = await ecr();
  const [registry, policy, scanning, rules, templates, settings] = await Promise.all([
    load(() => client.send(new DescribeRegistryCommand({}))),
    load(async () => (await client.send(new GetRegistryPolicyCommand({}))).policyText).then((r) => (!r.ok && /RegistryPolicyNotFound/.test(r.error) ? { ok: true as const, value: undefined } : r)),
    load(() => client.send(new GetRegistryScanningConfigurationCommand({}))),
    load(() =>
      all(
        (nextToken) => client.send(new DescribePullThroughCacheRulesCommand({ nextToken })),
        (r) => r.pullThroughCacheRules,
        (r) => r.nextToken,
      ),
    ),
    load(() =>
      all(
        (nextToken) => client.send(new DescribeRepositoryCreationTemplatesCommand({ nextToken })),
        (r) => r.repositoryCreationTemplates,
        (r) => r.nextToken,
      ),
    ),
    Promise.all(SETTINGS.map(([name]) => load(async () => (await client.send(new GetAccountSettingCommand({ name }))).value))),
  ]);
  const replRules = registry.ok ? (registry.value.replicationConfiguration?.rules ?? []) : [];
  const destinations = replRules.flatMap((r) => r.destinations ?? []);
  const prefixes = replRules.flatMap((r) => (r.repositoryFilters ?? []).map((f) => f.filter!));
  const scan = scanning.ok ? scanning.value.scanningConfiguration : undefined;
  const scanRule = scan?.rules?.[0];
  return {
    actions: undefined,
    body: (
      <>
        <Section
          title="Replication"
          actions={
            <Sheet title="Replication" label="Edit replication" icon={<Pencil size={15} aria-hidden />} testId="edit-replication">
              <ActionForm action={saveReplication} submit="Save" testId="edit-replication">
                <Field label="Destinations" hint="One per line: region, or region account (empty turns replication off)">
                  <textarea name="destinations" rows={3} defaultValue={destinations.map((d) => `${d.region} ${d.registryId}`).join("\n")} />
                </Field>
                <input type="hidden" name="account" value={registry.ok ? registry.value.registryId : ""} />
                <Field label="Repository prefixes" hint="Comma-separated; empty replicates every repository">
                  <input name="prefixes" defaultValue={prefixes.join(", ")} />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {!registry.ok ? (
            <ErrorNotice error={registry.error} />
          ) : destinations.length ? (
            <Facts items={[["Destinations", destinations.map((d) => `${d.region} (${d.registryId})`).join(", ")], ["Repositories", prefixes.length ? prefixes.map((p) => `${p}*`).join(", ") : "All"]]} />
          ) : (
            <span className="muted">Off</span>
          )}
        </Section>
        <Section
          title="Pull through cache rules"
          count={rules.ok ? rules.value.length : undefined}
          plain
          actions={
            <Sheet title="Create pull through cache rule" label="Create pull through cache rule" icon={<Plus size={15} aria-hidden />} testId="create-pull-through">
              <ActionForm action={createPullThrough} submit="Create" testId="create-pull-through">
                <Field label="Repository prefix" rule={CreatePullThroughCacheRule.ecrRepositoryPrefix} member="ecrRepositoryPrefix">
                  <input name="prefix" required placeholder="ecr-public" />
                </Field>
                <Field label="Upstream" rule={CreatePullThroughCacheRule.upstreamRegistry} member="upstreamRegistry">
                  <select name="upstream" defaultValue="ecr-public">
                    {(CreatePullThroughCacheRule.upstreamRegistry?.enum ?? []).map((u) => (
                      <option key={u}>{u}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Upstream registry URL" member="upstreamRegistryUrl">
                  <input name="url" required defaultValue="public.ecr.aws" />
                </Field>
                <Field label="Credentials (Secrets Manager ARN)" rule={{ ...CreatePullThroughCacheRule.credentialArn, required: false }} member="credentialArn" hint="ecr-pullthroughcache/… secret; Docker Hub, GitHub and others need one">
                  <input name="credential" />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {!rules.ok ? (
            <ErrorNotice error={rules.error} />
          ) : (
            <List
              label="Pull through cache rules"
              empty={<span className="muted">None</span>}
              rows={rules.value.map((r) => ({
                key: r.ecrRepositoryPrefix!,
                title: `${r.ecrRepositoryPrefix}/`,
                subtitle: (
                  <>
                    {r.upstreamRegistryUrl}
                    {r.credentialArn && (
                      <>
                        {" · "}
                        <Link href={links.secret(r.credentialArn)}>{shortName(r.credentialArn)}</Link>
                      </>
                    )}
                  </>
                ),
                meta: r.upstreamRegistry && <Pill>{r.upstreamRegistry}</Pill>,
                actions: <ActionForm action={deletePullThrough.bind(null, r.ecrRepositoryPrefix!)} submit={`Delete rule ${r.ecrRepositoryPrefix}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete the ${r.ecrRepositoryPrefix} rule?`} />,
              }))}
            />
          )}
        </Section>
        <Section
          title="Repository creation templates"
          count={templates.ok ? templates.value.length : undefined}
          plain
          actions={
            <Sheet title="Create template" label="Create repository creation template" icon={<Plus size={15} aria-hidden />} testId="create-template">
              <ActionForm action={createTemplate} submit="Create" testId="create-template">
                <Field label="Prefix" rule={CreateRepositoryCreationTemplate.prefix} hint="ROOT matches every repository">
                  <input name="prefix" required />
                </Field>
                <Field label="Description" rule={CreateRepositoryCreationTemplate.description}>
                  <input name="description" />
                </Field>
                <fieldset className="field">
                  <legend className="field-label">Applied for</legend>
                  {[
                    ["CREATE_ON_PUSH", "Create on push"],
                    ["PULL_THROUGH_CACHE", "Pull through cache"],
                    ["REPLICATION", "Replication"],
                  ].map(([v, l]) => (
                    <label key={v} className="check">
                      <input type="checkbox" name="appliedFor" value={v} defaultChecked={v === "CREATE_ON_PUSH"} /> {l}
                    </label>
                  ))}
                </fieldset>
                <div className="form-row">
                  <Field label="Encryption">
                    <select name="encryption" defaultValue="">
                      <option value="">AES-256</option>
                      <option value="KMS">AWS KMS</option>
                    </select>
                  </Field>
                  <Field label="KMS key ARN" member="encryptionConfiguration.kmsKey">
                    <input name="kms" />
                  </Field>
                </div>
                <div className="form-row">
                  <Field label="Keep last N images">
                    <input name="keep" type="number" min={0} />
                  </Field>
                  <label className="check">
                    <input type="checkbox" name="immutable" /> Immutable tags
                  </label>
                </div>
              </ActionForm>
            </Sheet>
          }
        >
          {!templates.ok ? (
            <ErrorNotice error={templates.error} />
          ) : (
            <List
              label="Repository creation templates"
              empty={<span className="muted">None</span>}
              rows={templates.value.map((t) => ({
                key: t.prefix!,
                title: t.prefix,
                subtitle: [t.description, t.imageTagMutability, t.encryptionConfiguration?.encryptionType].filter(Boolean).join(" · "),
                meta: (t.appliedFor ?? []).map((a) => <Pill key={a}>{a}</Pill>),
                actions: <ActionForm action={deleteTemplate.bind(null, t.prefix!)} submit={`Delete template ${t.prefix}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Delete template ${t.prefix}?`} />,
              }))}
            />
          )}
        </Section>
        <Section
          title="Scanning configuration"
          actions={
            <Sheet title="Scanning configuration" label="Edit scanning configuration" icon={<Pencil size={15} aria-hidden />} testId="edit-scanning">
              <ActionForm action={saveScanning} submit="Save" testId="edit-scanning">
                <Field label="Scan type">
                  <select name="scanType" defaultValue={scan?.scanType ?? "BASIC"}>
                    <option value="BASIC">Basic</option>
                    <option value="ENHANCED">Enhanced</option>
                  </select>
                </Field>
                <Field label="Frequency">
                  <select name="frequency" defaultValue={scanRule?.scanFrequency ?? ""}>
                    <option value="">Manual only</option>
                    <option value="SCAN_ON_PUSH">Scan on push</option>
                    <option value="CONTINUOUS_SCAN">Continuous</option>
                  </select>
                </Field>
                <Field label="Repository filters" hint="Wildcards, comma-separated; * for all">
                  <input name="filters" defaultValue={(scanRule?.repositoryFilters ?? []).map((f) => f.filter).join(", ") || "*"} />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {!scanning.ok ? (
            <ErrorNotice error={scanning.error} />
          ) : (
            <Facts
              items={[
                ["Scan type", scan?.scanType ?? "BASIC"],
                ...(scan?.rules ?? []).map((r) => [r.scanFrequency, (r.repositoryFilters ?? []).map((f) => f.filter).join(", ")] as [string, string]),
              ]}
            />
          )}
        </Section>
        <Section
          title="Registry permissions"
          actions={
            <Sheet title="Registry policy" label="Edit registry policy" icon={<Pencil size={15} aria-hidden />} testId="edit-registry-policy">
              <ActionForm action={saveRegistryPolicy} submit="Save" testId="edit-registry-policy">
                <Field label="Policy JSON" format="policy" hint="Empty removes the policy">
                  <textarea name="policy" rows={12} defaultValue={policy.ok && policy.value ? JSON.stringify(JSON.parse(policy.value), null, 2) : ""} />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {!policy.ok ? <ErrorNotice error={policy.error} /> : policy.value ? <CodeBlock value={policy.value} label="Registry policy" /> : <span className="muted">None</span>}
        </Section>
        <Section title="Account settings">
          <Facts
            items={SETTINGS.map(([name, values], i) => {
              const s = settings[i];
              const value = s.ok ? s.value : undefined;
              return [
                name,
                s.ok ? (
                  <span className="inline-icon">
                    <Status tone="neutral">{value ?? ""}</Status>
                    {values
                      .filter((v) => v !== value)
                      .map((v) => (
                        <ActionForm key={v} action={setAccountSetting.bind(null, name, v)} submit={`Set ${v}`} tone="plain" inline confirm={`Set ${name} to ${v}?`} />
                      ))}
                  </span>
                ) : (
                  s.error
                ),
              ] as [string, ReactNode];
            })}
          />
        </Section>
      </>
    ),
  };
}

export default async function Repositories({ searchParams }: Props) {
  const { tab = "private" } = await searchParams;
  const view = tab === "public" ? await Public() : tab === "registry" ? await Registry() : await Private();
  return (
    <Page title={TABS.find(([t]) => t === tab)?.[1] ?? "Private repositories"} actions={view.actions}>
      <Segments items={TABS.map(([t, l]) => ({ label: l, href: t === "private" ? "/ecr" : `/ecr?tab=${t}`, active: t === tab }))} />
      {view.body}
    </Page>
  );
}
