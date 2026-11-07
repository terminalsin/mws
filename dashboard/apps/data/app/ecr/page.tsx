import { DescribeRepositoriesCommand } from "@aws-sdk/client-ecr";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Sheet } from "@mws-dashboard/ui";
import { Lock, ScanSearch } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ecr } from "../../lib/clients";
import { createRepository } from "./actions";

export const metadata: Metadata = { title: "ECR" };

function CreateRepository() {
  return (
    <Sheet title="Create repository" label="Create repository" testId="create-repository">
      <ActionForm action={createRepository} submit="Create" testId="create-repository">
        <Field label="Repository name">
          <input name="name" required pattern="[a-z0-9][a-z0-9._/\-]*" autoFocus placeholder="team/app" />
        </Field>
        <label className="check">
          <input type="checkbox" name="immutable" /> Immutable tags
        </label>
        <label className="check">
          <input type="checkbox" name="scan" defaultChecked /> Scan on push
        </label>
        <Field label="Keep last N images">
          <input name="keep" type="number" min={0} placeholder="All" />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

export default async function Repositories() {
  const repos = await load(async () => {
    const client = await ecr();
    return collect(
      (nextToken) => client.send(new DescribeRepositoriesCommand({ nextToken })),
      (r) => r.repositories,
      (r) => r.nextToken,
    );
  });
  return (
    <Page title="Private repositories" actions={<CreateRepository />}>
      {repos.ok ? (
        <List
          label="Repositories"
          empty={<Empty icon={ICONS.ecr} action={<CreateRepository />} />}
          rows={repos.value
            .sort((a, b) => a.repositoryName!.localeCompare(b.repositoryName!))
            .map((r) => ({
              key: r.repositoryArn!,
              icon: <AwsIcon icon={ICONS.repo} size={24} />,
              title: r.repositoryName,
              subtitle: <code className="clip">{r.repositoryUri}</code>,
              href: `/ecr/repo?name=${encodeURIComponent(r.repositoryName!)}`,
              meta: (
                <>
                  {r.imageTagMutability === "IMMUTABLE" && <Lock size={13} aria-label="Immutable tags" />}
                  {r.imageScanningConfiguration?.scanOnPush && <ScanSearch size={14} aria-label="Scan on push" />}
                  <span>{ago(r.createdAt)}</span>
                </>
              ),
            }))}
        />
      ) : (
        <ErrorNotice error={repos.error} />
      )}
    </Page>
  );
}
