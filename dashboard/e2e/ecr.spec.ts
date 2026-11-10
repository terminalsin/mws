import {
  CompleteLayerUploadCommand,
  CreateRepositoryCommand,
  ECRClient,
  InitiateLayerUploadCommand,
  PutImageCommand,
  UploadLayerPartCommand,
} from "@aws-sdk/client-ecr";
import { createHash } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("ECR: create a repository with a lifecycle rule", async ({ page }) => {
  const name = unique("dash/app");
  await page.goto("/ecr");
  await submit(page, "create-repository", { name, keep: "10" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("Keep the last 10 images");
  await expect(page.locator("pre[aria-label='Push commands']")).toContainText("docker push");
});

async function openCreate(page: Page) {
  const form = page.locator("dialog[open]").getByTestId("create-repository").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("create-repository-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const name = form.locator('input[name="name"]');
  return { form, name, field: form.locator(".field").filter({ has: page.locator('input[name="name"]') }) };
}

test("ECR: repository names are repaired in the field", async ({ page }) => {
  await page.goto("/ecr");
  const { form, name, field } = await openCreate(page);

  // Uppercase and spaces: reshaped to ECR's lowercase, separated words.
  const base = unique("Dash App").replace("Dash App", "Dash/My App");
  await name.fill(base);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "pattern");
  const fixed = base.toLowerCase().replace(" ", "-");
  await field.getByRole("button", { name: /Lowercase/ }).click();
  await expect(name).toHaveValue(fixed);
  await expect(field).not.toHaveAttribute("data-invalid");

  // Doubled and trailing separators are tidied.
  await name.fill(`${fixed}//`);
  await name.blur();
  await field.getByRole("button", { name: /Tidy separators/ }).click();
  await expect(name).toHaveValue(fixed);

  // Too short: blocked in place, with a generated name.
  await name.fill("a");
  await form.locator('button[type="submit"]').click();
  await expect(field).toHaveAttribute("data-invalid", "tooShort");
  await expect(name).toBeFocused();
  await field.getByRole("button", { name: /Generate/ }).click();
  await expect(field).not.toHaveAttribute("data-invalid");
});

test("ECR: taken names and server conflicts suggest the next free name", async ({ page }) => {
  const client = new ECRClient(sdk);
  const taken = unique("dash/taken");
  await client.send(new CreateRepositoryCommand({ repositoryName: taken }));

  // Known when the page loaded: flagged before submitting.
  await page.goto("/ecr");
  let { name, field } = await openCreate(page);
  await name.fill(taken);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(field.getByRole("button", { name: /Use / })).toContainText(`${taken}-2`);

  // Created after the page loaded: RepositoryAlreadyExistsException lands on
  // the name field with the same repair, and the repaired name goes through.
  const later = unique("dash/later");
  await page.goto("/ecr");
  ({ name, field } = await openCreate(page));
  await client.send(new CreateRepositoryCommand({ repositoryName: later }));
  await name.fill(later);
  await page.locator("dialog[open]").locator('button[type="submit"]').click();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field.getByRole("button", { name: /Use / }).click();
  await expect(name).toHaveValue(`${later}-2`);
  await page.locator("dialog[open]").locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: `${later}-2` })).toBeVisible();
});

/** Push a one-platform image and an index over it, the way docker buildx does. */
async function seedIndex(client: ECRClient, repo: string) {
  const blob = Buffer.from("{}");
  const config = `sha256:${createHash("sha256").update(blob).digest("hex")}`;
  const { uploadId } = await client.send(new InitiateLayerUploadCommand({ repositoryName: repo }));
  await client.send(new UploadLayerPartCommand({ repositoryName: repo, uploadId, partFirstByte: 0, partLastByte: blob.length - 1, layerPartBlob: blob }));
  await client.send(new CompleteLayerUploadCommand({ repositoryName: repo, uploadId, layerDigests: [config] }));
  const child = JSON.stringify({ schemaVersion: 2, mediaType: "application/vnd.oci.image.manifest.v1+json", config: { mediaType: "application/vnd.oci.image.config.v1+json", digest: config, size: blob.length }, layers: [] });
  const childDigest = (await client.send(new PutImageCommand({ repositoryName: repo, imageManifest: child, imageManifestMediaType: "application/vnd.oci.image.manifest.v1+json", imageTag: "amd64" }))).image!.imageId!.imageDigest!;
  const index = JSON.stringify({
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [{ mediaType: "application/vnd.oci.image.manifest.v1+json", digest: childDigest, size: child.length, platform: { os: "linux", architecture: "amd64" } }],
  });
  const indexDigest = (await client.send(new PutImageCommand({ repositoryName: repo, imageManifest: index, imageManifestMediaType: "application/vnd.oci.image.index.v1+json", imageTag: "latest" }))).image!.imageId!.imageDigest!;
  return { childDigest, indexDigest };
}

test("ECR: image detail shows the index, manifest and scan, and reports delete failures", async ({ page }) => {
  const client = new ECRClient(sdk);
  const repo = unique("dash/images");
  await client.send(new CreateRepositoryCommand({ repositoryName: repo }));
  const { childDigest, indexDigest } = await seedIndex(client, repo);

  // The repository lists both, the index marked as such.
  await page.goto(`/ecr/repo?name=${encodeURIComponent(repo)}`);
  await expect(row(page, "latest")).toContainText("Index");
  await row(page, "latest").getByRole("link").first().click();

  // The index page lists its platform image and links to it.
  await expect(page.getByRole("heading", { level: 1, name: "latest" })).toBeVisible();
  const child = page.locator("li.row").filter({ hasText: "linux/amd64" });
  await expect(child).toContainText(childDigest);
  await page.getByText("Manifest", { exact: true }).click();
  await expect(page.locator("pre[aria-label='Image manifest']")).toContainText("application/vnd.oci.image.index.v1+json");
  await child.getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1, name: "amd64" })).toBeVisible();

  // The image is in use by the index: BatchDeleteImage answers 200 with a
  // failure, which the console must show rather than report success.
  page.once("dialog", (d) => d.accept().catch(() => {}));
  const del = page.getByTestId("delete-image").and(page.locator("form"));
  await del.locator('button[type="submit"]').click();
  await expect(del.getByRole("status")).toContainText("ImageReferencedByManifestList");
  await expect(page.getByRole("heading", { level: 1, name: "amd64" })).toBeVisible();

  // A scan can be started from the image.
  const scan = page.getByTestId("start-scan").and(page.locator("form"));
  await scan.locator('button[type="submit"]').click();
  await expect(scan.getByRole("status")).toHaveText("Scan started");
  await expect(page.locator("main")).toContainText(/Vulnerabilities/);

  // Deleting the index first works, and returns to the repository.
  await page.goto(`/ecr/image?repo=${encodeURIComponent(repo)}&digest=${indexDigest}`);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-image").and(page.locator("form")).locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: repo })).toBeVisible();
  await expect(row(page, "latest")).toHaveCount(0);
});

test("ECR: repository settings and policy", async ({ page }) => {
  const repo = unique("dash/settings");
  await new ECRClient(sdk).send(new CreateRepositoryCommand({ repositoryName: repo }));
  await page.goto(`/ecr/repo?name=${encodeURIComponent(repo)}`);
  await submit(page, "edit-repository", { mutability: "IMMUTABLE", scan: "on" });
  await expect(page.locator(".specs")).toContainText(/Immutable/i);

  await page.goto(`/ecr/repo?name=${encodeURIComponent(repo)}&tab=permissions`);
  const policy = JSON.stringify({ Version: "2012-10-17", Statement: [{ Sid: "pull", Effect: "Allow", Principal: { AWS: "arn:aws:iam::123456789012:root" }, Action: ["ecr:BatchGetImage"] }] });
  await submit(page, "edit-repository-policy", { policy });
  await expect(page.locator("pre[aria-label='Repository policy']")).toContainText("ecr:BatchGetImage");
});

test("ECR Public: create a repository, edit its catalog data and delete it", async ({ page }) => {
  const name = unique("dash-public");
  await page.goto("/ecr?tab=public");
  await submit(page, "create-public-repository", { name, description: "First" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator("main")).toContainText("First");
  await submit(page, "edit-catalog", { description: "Second", architectures: "x86-64, ARM 64" });
  await expect(page.locator("main")).toContainText("Second");
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-public-repository").and(page.locator("form")).locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/tab=public/);
  await expect(page.getByText(name)).toHaveCount(0);
});
