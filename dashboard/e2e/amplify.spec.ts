import { AmplifyClient, CreateAppCommand, CreateBranchCommand } from "@aws-sdk/client-amplify";
import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { row, sdk, submit, unique } from "./helpers";

test("Amplify: deploy a site to a branch", async ({ page, request }) => {
  const name = unique("dash-site");
  await page.goto("/amplify");
  await submit(page, "create-app", { name, branch: "main" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const appId = new URL(page.url()).searchParams.get("id")!;
  await row(page, "main").getByRole("link").first().click();
  await submit(page, "deploy", { html: `<h1>${name}</h1>` });
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Deployments").locator("li.row").first()).toContainText("succeed", { timeout: 1000 });
  }).toPass();
  const site = await request.get(`${sdk.endpoint}/_aws/amplify/sites/${appId}/main/`);
  expect(await site.text()).toContain(name);
});

/** Open the sheet behind `testId` and return its form. */
async function sheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, input: (name: string) => form.locator(`[name="${name}"]`) };
}

test("Amplify: forms repair branch names, URLs and taken branches in place", async ({ page }) => {
  const amplify = new AmplifyClient(sdk);
  const app = (await amplify.send(new CreateAppCommand({ name: unique("dash-valid") }))).app!;
  await amplify.send(new CreateBranchCommand({ appId: app.appId!, branchName: "main" }));

  // Create app: a Git-invalid branch name is fixed in one click, an SSH
  // remote becomes its HTTPS URL, a repository without a token is flagged
  // on the token.
  await page.goto("/amplify");
  let { form, field, input } = await sheet(page, "create-app");
  // A Git host adds the repository and token fields (an upload needs neither).
  await form.getByTestId("source-github").click();
  await expect(form.getByTestId("source-github")).toHaveAttribute("aria-checked", "true");
  await input("branch").fill("my feature");
  await input("branch").blur();
  await expect(field("branch")).toHaveAttribute("data-invalid", "format");
  await field("branch").getByRole("button", { name: /Fix the branch name/ }).click();
  await expect(input("branch")).toHaveValue("my-feature");
  await expect(field("branch")).not.toHaveAttribute("data-invalid");
  await input("repository").fill("git@github.com:org/site.git");
  await input("repository").blur();
  await field("repository").getByRole("button", { name: /HTTPS URL/ }).click();
  await expect(input("repository")).toHaveValue("https://github.com/org/site.git");
  await input("name").fill(unique("dash-norepo"));
  await form.locator('button[type="submit"]').click();
  await expect(field("token")).toHaveAttribute("data-invalid", "required");
  await expect(form.locator(".result.error")).toHaveCount(0);

  // Connect branch: a name the app has is flagged before submitting; one
  // added since the page loaded comes back from Amplify onto the field.
  await page.goto(`/amplify/app?id=${app.appId}`);
  ({ form, field, input } = await sheet(page, "create-branch"));
  await input("name").fill("main");
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(field("name").getByRole("button", { name: /Use / })).toContainText("main-2");
  await amplify.send(new CreateBranchCommand({ appId: app.appId!, branchName: "dev" }));
  await input("name").fill("dev");
  await form.locator('button[type="submit"]').click();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(form.locator(".result.error")).toHaveCount(0);
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(input("name")).toHaveValue("dev-2");

  // Deploy: a bare bucket path gets its scheme; nothing to deploy lands on
  // index.html.
  await page.goto(`/amplify/branch?app=${app.appId}&name=main`);
  ({ form, field, input } = await sheet(page, "deploy"));
  await input("url").fill("my-bucket/site.zip");
  await input("url").blur();
  await expect(field("url")).toHaveAttribute("data-invalid", "pattern");
  await field("url").getByRole("button", { name: /Add s3:\/\// }).click();
  await expect(input("url")).toHaveValue("s3://my-bucket/site.zip");
  await input("url").fill("");
  await form.locator('button[type="submit"]').click();
  await expect(field("html")).toHaveAttribute("data-invalid", "required");
});

/** A local Git repository MWS can clone, whose build echoes `marker`. */
function gitRepo(marker: string) {
  const dir = mkdtempSync(join(tmpdir(), "dash-amplify-"));
  writeFileSync(
    join(dir, "amplify.yml"),
    `version: 1\nfrontend:\n  phases:\n    build:\n      commands:\n        - echo ${marker}\n        - mkdir -p public && echo "<h1>${marker}</h1>" > public/index.html\n  artifacts:\n    baseDirectory: public\n    files:\n      - '**/*'\n`,
  );
  const git = (...args: string[]) => execFileSync("git", args, { cwd: dir, stdio: "pipe" });
  git("init", "-q", "-b", "main");
  git("add", ".");
  git("-c", "user.email=dash@example.com", "-c", "user.name=dash", "commit", "-q", "-m", "first");
  return dir;
}

test("Amplify: a new repository branch builds on request, with its steps and log, and from a webhook", async ({ page }) => {
  const marker = unique("dash-built");
  const amplify = new AmplifyClient(sdk);
  const app = (await amplify.send(new CreateAppCommand({ name: unique("dash-repo"), repository: gitRepo(marker), accessToken: "unused" }))).app!;
  await amplify.send(new CreateBranchCommand({ appId: app.appId!, branchName: "main" }));
  await page.goto(`/amplify/branch?app=${app.appId}&name=main`);
  await page.getByTestId("run-first-build").getByRole("button").click();
  const job = page.getByLabel("Deployments").locator("li.row").first();
  await expect(job).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(job).toContainText("succeed", { timeout: 1000 });
  }).toPass({ timeout: 90_000 });
  await job.getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("#1");
  await expect(page.getByLabel("Steps").locator("li.row").filter({ hasText: "BUILD" })).toBeVisible();
  await page.getByLabel("Steps").locator("li.row").filter({ hasText: "BUILD" }).getByRole("link").click();
  await expect(page.getByTestId("job-log")).toContainText(marker);

  // A webhook starts the next job.
  await page.goto(`/amplify/app?id=${app.appId}`);
  await submit(page, "create-webhook", { branch: "main", description: "ci" });
  await page.keyboard.press("Escape");
  await expect(row(page, "ci")).toBeVisible();
  await row(page, "ci").getByRole("button", { name: "Trigger ci" }).click();
  await page.goto(`/amplify/branch?app=${app.appId}&name=main`);
  await expect(page.getByLabel("Deployments").locator("li.row").filter({ hasText: "web hook" })).toBeVisible();
});

test("Amplify: app settings, branch settings and a custom domain", async ({ page }) => {
  const amplify = new AmplifyClient(sdk);
  const app = (await amplify.send(new CreateAppCommand({ name: unique("dash-edit") }))).app!;
  await amplify.send(new CreateBranchCommand({ appId: app.appId!, branchName: "main" }));
  await page.goto(`/amplify/app?id=${app.appId}`);
  // Rewrites wait under More.
  await (await sheet(page, "edit-app")).form.locator(".more-fields > summary").click();
  await submit(page, "edit-app", { env: "API_URL=https://api.example.com", rules: "/old /new 301" });
  await expect(page.getByText("API_URL", { exact: true })).toBeVisible();
  await expect(row(page, "/old")).toContainText("301");

  await page.goto(`/amplify/branch?app=${app.appId}&name=main`);
  await submit(page, "edit-branch", { stage: "BETA", env: "STAGE=beta" });
  await expect(page.locator(".specs")).toContainText("beta");
  await expect(page.getByText("STAGE", { exact: true })).toBeVisible();

  const domain = `${unique("dash").toLowerCase()}.example.com`;
  await page.goto(`/amplify/app?id=${app.appId}`);
  await submit(page, "create-domain", { domain, subDomains: "@=main\nwww=main" });
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  await expect(row(page, `www.${domain}`)).toBeVisible();
  await expect(row(page, `www.${domain}`)).toContainText("CNAME");
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByRole("button", { name: "Remove domain" }).click();
  await expect(page).toHaveURL(new RegExp(`/amplify/app\\?id=${app.appId}`));
});
