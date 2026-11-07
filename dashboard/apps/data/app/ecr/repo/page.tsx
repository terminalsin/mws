import { DescribeImagesCommand, DescribeRepositoriesCommand, GetLifecyclePolicyCommand } from "@aws-sdk/client-ecr";
import { ago, bytes, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, List, Page, Pill, Section, Specs, Status } from "@mws-dashboard/ui";
import { Lock, Recycle, ScanSearch, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ecr } from "../../../lib/clients";
import { deleteImage, deleteRepository } from "../actions";

export const metadata: Metadata = { title: "Repository" };

type Props = { searchParams: Promise<{ name?: string }> };

const SEVERITY_TONE: Record<string, "bad" | "warn" | "neutral"> = { CRITICAL: "bad", HIGH: "bad", MEDIUM: "warn", LOW: "neutral" };

export default async function Repository({ searchParams }: Props) {
  const { name = "" } = await searchParams;
  const back = { href: "/ecr", label: "Repositories" };
  const data = await load(async () => {
    const client = await ecr();
    const [repo, images, lifecycle] = await Promise.all([
      client.send(new DescribeRepositoriesCommand({ repositoryNames: [name] })).then((r) => r.repositories![0]),
      collect(
        (nextToken) => client.send(new DescribeImagesCommand({ repositoryName: name, nextToken })),
        (r) => r.imageDetails,
        (r) => r.nextToken,
      ),
      client.send(new GetLifecyclePolicyCommand({ repositoryName: name })).then((r) => r.lifecyclePolicyText, () => undefined),
    ]);
    return { repo, images, lifecycle };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.repo} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { repo, images, lifecycle } = data.value;
  const registry = repo.repositoryUri!.split("/")[0];
  const push = [
    `aws ecr get-login-password | docker login --username AWS --password-stdin ${registry}`,
    `docker tag app:latest ${repo.repositoryUri}:latest`,
    `docker push ${repo.repositoryUri}:latest`,
  ].join("\n");
  return (
    <Page
      title={name}
      icon={ICONS.repo}
      back={back}
      subtitle={repo.repositoryUri}
      actions={<ActionForm action={deleteRepository.bind(null, name)} submit="Delete repository" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name} and its images?`} testId="delete-repository" />}
    >
      <Specs
        items={[
          { label: "Images", icon: <AwsIcon icon={ICONS.image} size={16} />, value: images.length },
          repo.imageTagMutability === "IMMUTABLE" && { label: "Tags", icon: <Lock size={15} />, value: "Immutable" },
          repo.imageScanningConfiguration?.scanOnPush && { label: "Scanning", icon: <ScanSearch size={15} />, value: "Scan on push" },
          lifecycle && { label: "Lifecycle policy", icon: <Recycle size={15} />, value: (JSON.parse(lifecycle).rules ?? []).map((r: { description?: string }) => r.description).join(", ") || "Set" },
        ]}
      />
      <List
        label="Images"
        empty={
          <Section title="Push commands">
            <CodeBlock value={push} label="Push commands" />
          </Section>
        }
        rows={images
          .sort((a, b) => (b.imagePushedAt?.getTime() ?? 0) - (a.imagePushedAt?.getTime() ?? 0))
          .map((i) => {
            const counts: Record<string, number | undefined> = i.imageScanFindingsSummary?.findingSeverityCounts ?? {};
            const worst = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].find((s) => counts[s]);
            return {
              key: i.imageDigest!,
              icon: <AwsIcon icon={i.artifactMediaType?.includes("helm") ? "brand/helm" : "brand/docker"} size={22} />,
              title: i.imageTags?.length ? i.imageTags.join(", ") : <span className="muted">untagged</span>,
              subtitle: <code className="clip">{i.imageDigest}</code>,
              meta: (
                <>
                  {worst && (
                    <Pill tone={SEVERITY_TONE[worst]}>
                      {counts[worst]} {worst.toLowerCase()}
                    </Pill>
                  )}
                  {i.imageScanStatus?.status === "COMPLETE" && !worst && <Status tone="good">No findings</Status>}
                  <span>{bytes(i.imageSizeInBytes)}</span>
                  <span>{ago(i.imagePushedAt)}</span>
                </>
              ),
              actions: <ActionForm action={deleteImage.bind(null, name, i.imageDigest!)} submit={`Delete ${i.imageTags?.[0] ?? i.imageDigest}`} icon={<Trash2 size={15} />} tone="danger" confirm="Delete this image?" />,
            };
          })}
      />
      {images.length > 0 && (
        <details>
          <summary>Push commands</summary>
          <CodeBlock value={push} label="Push commands" />
        </details>
      )}
    </Page>
  );
}
