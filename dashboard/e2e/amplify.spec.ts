import { AmplifyClient, CreateAppCommand, CreateBranchCommand } from "@aws-sdk/client-amplify";
import { expect, test, type Page } from "@playwright/test";

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
