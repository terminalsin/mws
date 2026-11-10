import {
  DescribeImagesCommand,
  DescribeRepositoriesCommand,
  GetRepositoryCatalogDataCommand,
  GetRepositoryPolicyCommand,
} from "@aws-sdk/client-ecr-public";
import { ago, all, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { Pencil, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ecrPublic } from "../../../lib/clients";
import { deletePublicRepository, savePublicCatalog, savePublicPolicy } from "../actions";
import { PolicyEditor } from "@mws-dashboard/ui/policy";

export const metadata: Metadata = { title: "Public repository" };

type Props = { searchParams: Promise<{ name?: string }> };

export default async function PublicRepository({ searchParams }: Props) {
  const { name = "" } = await searchParams;
  const back = { href: "/ecr?tab=public", label: "Public repositories" };
  const client = await ecrPublic();
  const data = await load(async () => {
    const [repo, catalog, images, policy] = await Promise.all([
      client.send(new DescribeRepositoriesCommand({ repositoryNames: [name] })).then((r) => r.repositories![0]),
      client.send(new GetRepositoryCatalogDataCommand({ repositoryName: name })).then((r) => r.catalogData),
      all(
        (nextToken) => client.send(new DescribeImagesCommand({ repositoryName: name, nextToken })),
        (r) => r.imageDetails,
        (r) => r.nextToken,
      ),
      load(async () => {
        try {
          return (await client.send(new GetRepositoryPolicyCommand({ repositoryName: name }))).policyText;
        } catch (e) {
          if ((e as Error).name === "RepositoryPolicyNotFoundException") return undefined;
          throw e;
        }
      }),
    ]);
    return { repo, catalog, images, policy };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.repo} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { repo, catalog, images, policy } = data.value;
  return (
    <Page
      title={name}
      icon={ICONS.repo}
      back={back}
      subtitle={repo.repositoryUri}
      actions={
        <>
          <Sheet title="Catalog data" label="Edit catalog data" icon={<Pencil size={15} aria-hidden />} testId="edit-catalog">
            <ActionForm action={savePublicCatalog.bind(null, name)} submit="Save" testId="edit-catalog">
              <Field label="Description" rule={{ maxLength: 1024 }}>
                <input name="description" defaultValue={catalog?.description} />
              </Field>
              <div className="form-row">
                <Field label="Architectures">
                  <input name="architectures" defaultValue={(catalog?.architectures ?? []).join(", ")} />
                </Field>
                <Field label="Operating systems">
                  <input name="os" defaultValue={(catalog?.operatingSystems ?? []).join(", ")} />
                </Field>
              </div>
              <Field label="About (Markdown)">
                <textarea name="about" rows={4} defaultValue={catalog?.aboutText} />
              </Field>
              <Field label="Usage (Markdown)">
                <textarea name="usage" rows={4} defaultValue={catalog?.usageText} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm action={deletePublicRepository.bind(null, name)} submit="Delete repository" icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm={`Delete ${name} and its images?`} testId="delete-public-repository" />
        </>
      }
    >
      <Section title="Catalog">
        <Facts
          items={[
            catalog?.description && ["Description", catalog.description],
            catalog?.architectures?.length ? ["Architectures", catalog.architectures.map((a) => <Pill key={a}>{a}</Pill>)] : null,
            catalog?.operatingSystems?.length ? ["Operating systems", catalog.operatingSystems.map((a) => <Pill key={a}>{a}</Pill>)] : null,
            catalog?.marketplaceCertified && ["Marketplace certified", "Yes"],
            ["Created", ago(repo.createdAt)],
          ]}
        />
        {catalog?.aboutText && <CodeBlock value={catalog.aboutText} label="About" />}
        {catalog?.usageText && <CodeBlock value={catalog.usageText} label="Usage" />}
      </Section>
      <Section title="Images" count={images.length} plain>
        <List
          label="Images"
          empty={<span className="muted">None</span>}
          rows={images
            .sort((a, b) => (b.imagePushedAt?.getTime() ?? 0) - (a.imagePushedAt?.getTime() ?? 0))
            .map((i) => ({
              key: i.imageDigest!,
              icon: <AwsIcon icon="brand/docker" size={22} />,
              title: i.imageTags?.length ? i.imageTags.join(", ") : <span className="muted">untagged</span>,
              subtitle: <code className="clip">{i.imageDigest}</code>,
              meta: (
                <>
                  <span>{bytes(i.imageSizeInBytes)}</span>
                  <span>{ago(i.imagePushedAt)}</span>
                </>
              ),
            }))}
        />
      </Section>
      <Section
        title="Repository policy"
        actions={
          <Sheet title="Repository policy" label="Edit repository policy" icon={<Pencil size={15} aria-hidden />} testId="edit-public-policy">
            <ActionForm action={savePublicPolicy.bind(null, name)} submit="Save" testId="edit-public-policy">
              <PolicyEditor label="Policy JSON" format="policy" hint="Empty removes the policy" kind="resource" name="policy" rows={12} defaultValue={policy.ok && policy.value ? JSON.stringify(JSON.parse(policy.value), null, 2) : ""} />
            </ActionForm>
          </Sheet>
        }
      >
        {!policy.ok ? <ErrorNotice error={policy.error} /> : policy.value ? <CodeBlock value={policy.value} label="Repository policy" /> : <span className="muted">None</span>}
      </Section>
    </Page>
  );
}
