"use server";

import { BatchDeleteImageCommand, CreateRepositoryCommand, DeleteRepositoryCommand, PutLifecyclePolicyCommand } from "@aws-sdk/client-ecr";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ecr } from "../../lib/clients";

export async function createRepository(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Repository name");
    const client = await ecr();
    await client.send(
      new CreateRepositoryCommand({
        repositoryName: name,
        imageTagMutability: text(form, "immutable") === "on" ? "IMMUTABLE" : "MUTABLE",
        imageScanningConfiguration: { scanOnPush: text(form, "scan") === "on" },
      }),
    );
    const keep = Number(text(form, "keep") || 0);
    if (keep > 0) {
      await client.send(
        new PutLifecyclePolicyCommand({
          repositoryName: name,
          lifecyclePolicyText: JSON.stringify({ rules: [{ rulePriority: 1, description: `Keep the last ${keep} images`, selection: { tagStatus: "any", countType: "imageCountMoreThan", countNumber: keep }, action: { type: "expire" } }] }),
        }),
      );
    }
    redirect(`/ecr/repo?name=${encodeURIComponent(name)}`);
  }, { revalidate: ["/ecr"], fields: { repositoryName: "name", LifecyclePolicyValidationException: "keep" } });
}

export async function deleteRepository(name: string) {
  return act(async () => {
    await (await ecr()).send(new DeleteRepositoryCommand({ repositoryName: name, force: true }));
    redirect("/ecr");
  });
}

export async function deleteImage(repo: string, digest: string) {
  return act(async () => {
    await (await ecr()).send(new BatchDeleteImageCommand({ repositoryName: repo, imageIds: [{ imageDigest: digest }] }));
    return "Image deleted";
  }, "/ecr/repo");
}
