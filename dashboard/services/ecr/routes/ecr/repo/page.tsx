import {
  DescribeImagesCommand,
  DescribeRepositoriesCommand,
  GetLifecyclePolicyCommand,
  GetLifecyclePolicyPreviewCommand,
  GetRepositoryPolicyCommand,
  ListTagsForResourceCommand,
  type ImageDetail,
} from "@aws-sdk/client-ecr";
import { ago, all, bytes, load, shortName } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, CopyValue, Empty, ErrorNotice, Facts, Field, List, More, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { PutImageTagMutability } from "@mws-dashboard/ui/model/ecr";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { Archive, Eye, KeyRound, Lock, Pencil, Recycle, ScanSearch, Settings2, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, SEVERITY_TONE, ecr, imageHref, links, pushCommands, repoHref } from "../../../lib/clients";
import { deleteImage, deleteRepository, previewLifecycle, saveLifecyclePolicy, saveRepositoryPolicy, saveSettings, saveTags } from "../actions";
import { LifecycleForm } from "./lifecycle-form.tsx";

export const metadata: Metadata = { title: "Repository" };

type Props = { searchParams: Promise<{ name?: string; tab?: string; token?: string }> };

const TABS = [
  ["images", "Images"],
  ["permissions", "Permissions"],
  ["lifecycle", "Lifecycle Policy"],
  ["tags", "Repository tags"],
] as const;

const PAGE = 100;

function ScanPill({ i }: { i: ImageDetail }) {
  const counts: Record<string, number | undefined> = i.imageScanFindingsSummary?.findingSeverityCounts ?? {};
  const worst = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].find((s) => counts[s]);
  const status = i.imageScanStatus?.status;
  if (worst)
    return (
      <Pill tone={SEVERITY_TONE[worst]}>
        {counts[worst]} {worst.toLowerCase()}
      </Pill>
    );
  if (status === "COMPLETE") return <Status tone="good">No findings</Status>;
  if (status === "IN_PROGRESS" || status === "PENDING") return <Status tone="info">Scanning</Status>;
  if (status && status !== "ACTIVE") return <Pill tone={/FAILED|UNSUPPORTED/.test(status) ? "bad" : "neutral"} title={i.imageScanStatus?.description}>{status.toLowerCase().replace(/_/g, " ")}</Pill>;
  return null;
}

export default async function Repository({ searchParams }: Props) {
  const { name = "", tab = "images", token } = await searchParams;
  const back = { href: "/ecr", label: "Repositories" };
  const client = await ecr();
  const repo = await load(async () => (await client.send(new DescribeRepositoriesCommand({ repositoryNames: [name] }))).repositories![0]);
  if (!repo.ok) {
    return (
      <Page title={name} icon={ICONS.repo} back={back}>
        <ErrorNotice error={repo.error} />
      </Page>
    );
  }
  const r = repo.value;
  const lifecycle = await load(async () => {
    try {
      return (await client.send(new GetLifecyclePolicyCommand({ repositoryName: name }))).lifecyclePolicyText;
    } catch (e) {
      if ((e as Error).name === "LifecyclePolicyNotFoundException") return undefined;
      throw e;
    }
  });
  const policyRules = lifecycle.ok && lifecycle.value ? ((JSON.parse(lifecycle.value).rules ?? []) as { rulePriority?: number; description?: string; action?: { type?: string } }[]) : [];
  const mutability = r.imageTagMutability ?? "MUTABLE";
  const body = await (async () => {
    switch (tab) {
      case "permissions":
        return Permissions({ name });
      case "lifecycle":
        return Lifecycle({ name, text: lifecycle });
      case "tags":
        return RepoTags({ arn: r.repositoryArn! });
      default:
        return Images({ name, uri: r.repositoryUri!, token });
    }
  })();
  return (
    <Page
      title={name}
      icon={ICONS.repo}
      back={back}
      subtitle={r.repositoryUri}
      actions={
        <>
          <Sheet title="Repository settings" label="Edit repository" icon={<Settings2 size={15} aria-hidden />} testId="edit-repository">
            <ActionForm action={saveSettings.bind(null, name)} submit="Save" testId="edit-repository">
              <Field label="Tag mutability" rule={PutImageTagMutability.imageTagMutability} member="imageTagMutability">
                <select name="mutability" defaultValue={mutability}>
                  <option value="MUTABLE">Mutable</option>
                  <option value="IMMUTABLE">Immutable</option>
                  <option value="MUTABLE_WITH_EXCLUSION">Mutable, except matching tags</option>
                  <option value="IMMUTABLE_WITH_EXCLUSION">Immutable, except matching tags</option>
                </select>
              </Field>
              <Field label="Exclusion filters" rule={{ ...ruleAt(PutImageTagMutability, "imageTagMutabilityExclusionFilters.filter"), required: false }} hint="Wildcards like latest, dev-*; comma-separated" member="imageTagMutabilityExclusionFilters">
                <input name="exclusions" defaultValue={(r.imageTagMutabilityExclusionFilters ?? []).map((f) => f.filter).join(", ")} />
              </Field>
              <label className="check">
                <input type="checkbox" name="scan" defaultChecked={r.imageScanningConfiguration?.scanOnPush} /> Scan on push
              </label>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteRepository.bind(null, name)} submit="Delete repository" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name} and its images?`} testId="delete-repository" />
        </>
      }
    >
      <Specs
        items={[
          mutability !== "MUTABLE" && { label: "Tags", icon: <Lock size={15} />, value: mutability.replace(/_/g, " ").toLowerCase() },
          r.imageScanningConfiguration?.scanOnPush && { label: "Scanning", icon: <ScanSearch size={15} />, value: "Scan on push" },
          {
            label: "Encryption",
            icon: <KeyRound size={15} />,
            value: r.encryptionConfiguration?.kmsKey ? <Link href={links.key(r.encryptionConfiguration.kmsKey)}>{`${r.encryptionConfiguration.encryptionType} · ${shortName(r.encryptionConfiguration.kmsKey)}`}</Link> : (r.encryptionConfiguration?.encryptionType ?? "AES256"),
          },
          policyRules.length > 0 && { label: "Lifecycle policy", icon: <Recycle size={15} />, value: policyRules.map((x) => x.description).filter(Boolean).join(", ") || `${policyRules.length} rules` },
        ]}
      />
      {!lifecycle.ok && <ErrorNotice error={`Lifecycle policy: ${lifecycle.error}`} />}
      <Segments items={TABS.map(([t, l]) => ({ label: l, href: repoHref(name, t === "images" ? undefined : t), active: t === tab }))} />
      {body}
    </Page>
  );
}

async function Images({ name, uri, token }: { name: string; uri: string; token?: string }) {
  const client = await ecr();
  const page = await load(() => client.send(new DescribeImagesCommand({ repositoryName: name, nextToken: token, maxResults: PAGE })));
  const push = await pushCommands(uri);
  if (!page.ok) return <ErrorNotice error={page.error} />;
  const images = (page.value.imageDetails ?? []).sort((a, b) => (b.imagePushedAt?.getTime() ?? 0) - (a.imagePushedAt?.getTime() ?? 0));
  const scanning = images.some((i) => i.imageScanStatus?.status === "IN_PROGRESS" || i.imageStatus === "ACTIVATING");
  return (
    <>
      <LiveRefresh when={scanning} />
      <List
        label="Images"
        empty={
          <Section title="Push commands">
            <CodeBlock value={push} label="Push commands" />
          </Section>
        }
        rows={images.map((i) => {
          const archived = i.imageStatus === "ARCHIVED";
          return {
            key: i.imageDigest!,
            icon: <AwsIcon icon={i.artifactMediaType?.includes("helm") ? "brand/helm" : "brand/docker"} size={22} />,
            title: i.imageTags?.length ? i.imageTags.join(", ") : <span className="muted">untagged</span>,
            subtitle: <code className="clip">{i.imageDigest}</code>,
            href: imageHref(name, i.imageDigest!),
            meta: (
              <>
                {archived && <Pill icon={<Archive size={12} aria-hidden />}>Archived</Pill>}
                {i.imageStatus === "ACTIVATING" && <Status tone="info">Restoring</Status>}
                {/index|list/.test(i.imageManifestMediaType ?? "") && <Pill>Index</Pill>}
                <ScanPill i={i} />
                <span>{bytes(i.imageSizeInBytes)}</span>
                <span title={i.imagePushedAt?.toISOString()}>{ago(i.imagePushedAt)}</span>
              </>
            ),
            actions: (
              <ActionForm action={deleteImage.bind(null, name, i.imageDigest!, null)} submit={`Delete ${i.imageTags?.[0] ?? i.imageDigest}`} icon={<Trash2 size={15} />} tone="danger" confirm="Delete this image?" />
            ),
          };
        })}
      />
      <More shown={images.length} noun="images" href={page.value.nextToken ? `${repoHref(name)}&token=${encodeURIComponent(page.value.nextToken)}` : undefined} />
      {images.length > 0 && (
        <details>
          <summary>Push commands</summary>
          <CodeBlock value={push} label="Push commands" />
        </details>
      )}
    </>
  );
}

async function Permissions({ name }: { name: string }) {
  const policy = await load(async () => {
    try {
      return (await (await ecr()).send(new GetRepositoryPolicyCommand({ repositoryName: name }))).policyText;
    } catch (e) {
      if ((e as Error).name === "RepositoryPolicyNotFoundException") return undefined;
      throw e;
    }
  });
  const template = JSON.stringify(
    { Version: "2012-10-17", Statement: [{ Sid: "AllowPull", Effect: "Allow", Principal: { AWS: "arn:aws:iam::111122223333:root" }, Action: ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"] }] },
    null,
    2,
  );
  return (
    <Section
      title="Repository policy"
      actions={
        <Sheet title="Repository policy" label="Edit repository policy" icon={<Pencil size={15} aria-hidden />} testId="edit-repository-policy">
          <ActionForm action={saveRepositoryPolicy.bind(null, name)} submit="Save" testId="edit-repository-policy">
            <Field label="Policy JSON" format="policy" hint="Empty removes the policy">
              <textarea name="policy" rows={14} defaultValue={policy.ok && policy.value ? JSON.stringify(JSON.parse(policy.value), null, 2) : template} />
            </Field>
          </ActionForm>
        </Sheet>
      }
    >
      {!policy.ok ? <ErrorNotice error={policy.error} /> : policy.value ? <CodeBlock value={policy.value} label="Repository policy" /> : <span className="muted">None</span>}
    </Section>
  );
}

async function Lifecycle({ name, text }: { name: string; text: Awaited<ReturnType<typeof load<string | undefined>>> }) {
  const client = await ecr();
  const preview = await load(async () => {
    try {
      return await client.send(new GetLifecyclePolicyPreviewCommand({ repositoryName: name }));
    } catch (e) {
      if ((e as Error).name === "LifecyclePolicyPreviewNotFoundException") return undefined;
      throw e;
    }
  });
  const current = text.ok ? text.value : undefined;
  const p = preview.ok ? preview.value : undefined;
  const results = p
    ? await all(
        async (nextToken) => (nextToken ? await client.send(new GetLifecyclePolicyPreviewCommand({ repositoryName: name, nextToken })) : p),
        (r) => r.previewResults,
        (r) => r.nextToken,
      ).catch(() => p.previewResults ?? [])
    : [];
  return (
    <>
      <Section
        title="Lifecycle policy"
        actions={
          <>
            <Sheet title="Lifecycle policy" label="Edit lifecycle policy" icon={<Pencil size={15} aria-hidden />} testId="edit-lifecycle-policy">
              <LifecycleForm action={saveLifecyclePolicy.bind(null, name)} current={current} submit="Save" testId="edit-lifecycle-policy" hint="Empty removes the policy" />
            </Sheet>
            <Sheet title="Preview lifecycle policy" label="Preview lifecycle policy" icon={<Eye size={15} aria-hidden />} testId="preview-lifecycle">
              <LifecycleForm action={previewLifecycle.bind(null, name)} current={current} submit="Run preview" testId="preview-lifecycle" hint="Empty previews the saved policy" />
            </Sheet>
          </>
        }
      >
        {!text.ok ? <ErrorNotice error={text.error} /> : current ? <CodeBlock value={current} label="Lifecycle policy" /> : <span className="muted">None</span>}
      </Section>
      {!preview.ok ? (
        <ErrorNotice error={preview.error} />
      ) : (
        p && (
          <Section title="Preview" count={results.length} plain>
            <LiveRefresh when={p.status === "IN_PROGRESS"} />
            <p>
              <Status tone={p.status === "COMPLETE" ? "good" : p.status === "FAILED" ? "bad" : "info"}>{p.status ?? ""}</Status>
            </p>
            <List
              label="Images the policy would act on"
              empty={<span className="muted">No image would be affected</span>}
              rows={results.map((x) => ({
                key: x.imageDigest!,
                title: x.imageTags?.length ? x.imageTags.join(", ") : <span className="muted">untagged</span>,
                subtitle: <code className="clip">{x.imageDigest}</code>,
                href: imageHref(name, x.imageDigest!),
                meta: (
                  <>
                    <Pill tone="warn">{x.action?.type ?? "expire"}</Pill>
                    <Pill>rule {x.appliedRulePriority}</Pill>
                    <span>{ago(x.imagePushedAt)}</span>
                  </>
                ),
              }))}
            />
          </Section>
        )
      )}
    </>
  );
}

async function RepoTags({ arn }: { arn: string }) {
  const tags = await load(async () => (await (await ecr()).send(new ListTagsForResourceCommand({ resourceArn: arn }))).tags ?? []);
  return (
    <Section
      title="Repository tags"
      actions={
        <Sheet title="Tags" label="Edit tags" icon={<Pencil size={15} aria-hidden />} testId="edit-repo-tags">
          <ActionForm action={saveTags.bind(null, arn, tags.ok ? tags.value.map((t) => t.Key!) : [])} submit="Save" testId="edit-repo-tags">
            <Field label="One Key=Value per line" format="tags">
              <textarea name="tags" defaultValue={(tags.ok ? tags.value : []).map((t) => `${t.Key}=${t.Value}`).join("\n")} />
            </Field>
          </ActionForm>
        </Sheet>
      }
    >
      {!tags.ok ? <ErrorNotice error={tags.error} /> : tags.value.length ? <Tags tags={tags.value} /> : <span className="muted">None</span>}
      <Facts items={[["ARN", <CopyValue value={arn} label="Copy ARN" />]]} />
    </Section>
  );
}

