import { CodeartifactClient, CreateDomainCommand, CreateRepositoryCommand } from "@aws-sdk/client-codeartifact";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("CodeArtifact: a repository with an npm upstream and its connection instructions", async ({ page }) => {
  const domain = unique("dash").toLowerCase().slice(0, 40);
  const repo = unique("dash-npm");
  await page.goto("/codeartifact?tab=domains");
  await submit(page, "create-domain", { name: domain });
  await expect(row(page, domain)).toBeVisible();
  await page.goto("/codeartifact");
  await submit(page, "create-repository", { name: repo, domain, external: "public:npmjs" });
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
