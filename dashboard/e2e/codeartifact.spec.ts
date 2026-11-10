import {
  CodeartifactClient,
  CreateDomainCommand,
  CreateRepositoryCommand,
  PublishPackageVersionCommand,
  UpdatePackageVersionsStatusCommand,
} from "@aws-sdk/client-codeartifact";
import { expect, test, type Page } from "@playwright/test";
import { createHash } from "node:crypto";

import { row, rowAction, sdk, submit, unique } from "./helpers";

test("CodeArtifact: a repository with an npm upstream and its connection instructions", async ({ page }) => {
  const domain = unique("dash").toLowerCase().slice(0, 40);
  const repo = unique("dash-npm");
  await page.goto("/codeartifact?tab=domains");
  await submit(page, "create-domain", { name: domain });
  await expect(row(page, domain)).toBeVisible();
  await page.goto("/codeartifact");
  // The sheet opens on the public upstream; npm names the repository npm-store.
  const form = await openSheet(page, "create-repository");
  await form.getByTestId("preset-public:npmjs").click();
  await expect(form.locator('input[name="name"]')).toHaveValue(/^npm-store/);
  await submit(page, "create-repository", { name: repo, domain });
  await expect(page.getByRole("heading", { level: 1, name: repo })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("npmjs");
  await expect(page.locator("pre.code")).toContainText("npm config set registry");
  await expect(page.locator("pre.code")).toContainText(`/${domain}-`);
});

test("CodeArtifact: names are checked in place, per domain, with repairs", async ({ page }) => {
  const client = new CodeartifactClient(sdk);
  const domain = unique("dash-v").toLowerCase();
  const other = unique("dash-w").toLowerCase();
  const repo = unique("dash-repo");
  await client.send(new CreateDomainCommand({ domain }));
  await client.send(new CreateDomainCommand({ domain: other }));
  await client.send(new CreateRepositoryCommand({ domain, repository: repo }));

  // Domain names are lowercase: the field offers the lowercase form...
  await page.goto("/codeartifact?tab=domains");
  let form = await openSheet(page, "create-domain");
  let name = form.locator('input[name="name"]');
  let field = form.locator(".field").filter({ has: page.locator(`input[name="name"]`) });
  await name.fill("My Team Packages");
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "pattern");
  await field.getByRole("button", { name: /my-team-packages/ }).click();
  await expect(name).toHaveValue("my-team-packages");
  await expect(field).not.toHaveAttribute("data-invalid");
  // ...and an existing one the next free name.
  await name.fill(domain);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(field.getByRole("button", { name: /Use / })).toContainText(`${domain}-2`);

  // A repository name is taken only within its domain.
  await page.goto("/codeartifact");
  form = await openSheet(page, "create-repository");
  name = form.locator('input[name="name"]');
  field = form.locator(".field").filter({ has: page.locator(`input[name="name"]`) });
  await form.locator('select[name="domain"]').selectOption(domain);
  await name.fill(repo);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(form.locator('select[name="upstream"] option', { hasText: repo })).toHaveCount(1);
  await form.locator('select[name="domain"]').selectOption(other);
  await expect(field).not.toHaveAttribute("data-invalid");
  await expect(form.locator('select[name="upstream"]')).toHaveCount(0);

  // Created after the page loaded: MWS's ConflictException lands on the name.
  const later = unique("dash-later");
  await client.send(new CreateRepositoryCommand({ domain: other, repository: later }));
  await name.fill(later);
  await form.locator('button[type="submit"]').click();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(form.locator(".result.error")).toHaveCount(0);
  await expect(field.getByRole("button", { name: /Use / })).toContainText(`${later}-2`);

  // Too short for the model: a generated name repairs it.
  await name.fill("x");
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", /tooShort|pattern/);
  await field.locator("button.repair").first().click();
  await expect(field).not.toHaveAttribute("data-invalid");
  const generated = await name.inputValue();
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: generated })).toBeVisible();
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  return form;
}

/** A domain and repository holding generic package `ns/<pkg>` at the given versions. */
async function seed(versions: string[]) {
  const client = new CodeartifactClient(sdk);
  const domain = unique("dash-ca").toLowerCase().slice(0, 40);
  const repo = unique("dash-gen");
  const pkg = unique("tool").toLowerCase();
  await client.send(new CreateDomainCommand({ domain }));
  await client.send(new CreateRepositoryCommand({ domain, repository: repo }));
  for (const v of versions) {
    const body = Buffer.from(`asset of ${v}`);
    await client.send(
      new PublishPackageVersionCommand({
        domain,
        repository: repo,
        format: "generic",
        namespace: "ns",
        package: pkg,
        packageVersion: v,
        assetName: "tool.tgz",
        assetContent: body,
        assetSHA256: createHash("sha256").update(body).digest("hex"),
      }),
    );
  }
  const pkgUrl = `/codeartifact/package?domain=${domain}&repo=${repo}&format=generic&namespace=ns&package=${pkg}`;
  return { client, domain, repo, pkg, pkgUrl };
}

test("CodeArtifact: per-version failures are reported, disposed versions cannot be archived, assets download", async ({ page }) => {
  const { client, domain, repo, pkg, pkgUrl } = await seed(["1.0.0", "2.0.0"]);
  await page.goto(pkgUrl);
  await expect(row(page, "2.0.0")).toBeVisible();

  // Changed behind the page's back: AWS answers 200 with a per-version failure.
  await client.send(new UpdatePackageVersionsStatusCommand({ domain, repository: repo, format: "generic", namespace: "ns", package: pkg, versions: ["1.0.0"], targetStatus: "Unlisted" }));
  await rowAction(page, "1.0.0", "Unlist 1.0.0");
  await expect(page.getByText(/1\.0\.0: MISMATCHED_STATUS/).first()).toBeVisible();

  await page.reload();
  await rowAction(page, "1.0.0", "Dispose 1.0.0");
  await expect(row(page, "1.0.0")).toContainText("disposed");
  await expect(row(page, "1.0.0").getByRole("button", { name: "Archive 1.0.0" })).toHaveCount(0);

  // The version's own page: its asset, with hashes and a download.
  await row(page, "2.0.0").getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("2.0.0");
  const asset = row(page, "tool.tgz");
  await expect(asset).toContainText("SHA-256");
  const href = await asset.getByRole("link", { name: "Download tool.tgz" }).getAttribute("href");
  const res = await page.request.get(href!);
  expect(res.status()).toBe(200);
  expect(await res.text()).toBe("asset of 2.0.0");
});

test("CodeArtifact: origin controls and package groups", async ({ page }) => {
  const { domain, pkg, pkgUrl } = await seed(["1.0.0"]);
  await page.goto(pkgUrl);
  await submit(page, "origin-controls", { publish: "BLOCK", upstream: "ALLOW" });
  await expect(page.locator(".specs")).toContainText("blocked");

  await page.goto(`/codeartifact/domain?name=${domain}&tab=groups`);
  await submit(page, "create-package-group", { pattern: "/generic/ns/*", description: "Team tools" });
  await expect(page.getByRole("heading", { level: 1, name: "/generic/ns/*" })).toBeVisible();
  await expect(row(page, pkg)).toBeVisible();
  await submit(page, "group-origin", { mode_PUBLISH: "BLOCK", mode_EXTERNAL_UPSTREAM: "INHERIT", mode_INTERNAL_UPSTREAM: "INHERIT" });
  await expect(page.locator(".specs")).toContainText("block");

  // The package now names its group.
  await page.goto(pkgUrl);
  await expect(page.locator(".specs")).toContainText("/generic/ns/*");
});

test("CodeArtifact: a repository's upstreams are reordered and its public connection swapped", async ({ page }) => {
  const client = new CodeartifactClient(sdk);
  const domain = unique("dash-up").toLowerCase().slice(0, 40);
  const [a, b, c] = [unique("dash-a"), unique("dash-b"), unique("dash-c")];
  await client.send(new CreateDomainCommand({ domain }));
  for (const r of [a, b]) await client.send(new CreateRepositoryCommand({ domain, repository: r }));
  await client.send(new CreateRepositoryCommand({ domain, repository: c, upstreams: [{ repositoryName: a }] }));
  await page.goto(`/codeartifact/repo?domain=${domain}&name=${c}`);
  await submit(page, "edit-repository", { description: "Builds", upstreams: `${b}\n${a}` });
  const upstreams = page.getByRole("list", { name: "Upstreams" }).locator("li.row");
  await expect(upstreams).toHaveCount(2);
  await expect(upstreams.nth(0)).toContainText(b);
  await expect(upstreams.nth(1)).toContainText(a);

  await submit(page, "add-external", { external: "public:npmjs" });
  await expect(row(page, "public:npmjs")).toBeVisible();
  await rowAction(page, "public:npmjs", "Disconnect public:npmjs");
  await expect(row(page, "public:npmjs")).toHaveCount(0);
});
