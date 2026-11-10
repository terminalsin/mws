import { CreateRepositoryCommand, ECRClient } from "@aws-sdk/client-ecr";
import { expect, test, type Page } from "@playwright/test";

import { sdk, submit, unique } from "./helpers";

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
