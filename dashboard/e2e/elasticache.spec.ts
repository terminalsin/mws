import { expect, test, type Page } from "@playwright/test";

import { submit, unique } from "./helpers";

async function openSheet(page: Page) {
  await page.goto("/elasticache");
  const form = page.locator("dialog[open]").getByTestId("create-cache").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("create-cache-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, input: (name: string) => form.locator(`[name="${name}"]`) };
}

test("ElastiCache: create a serverless Valkey cache", async ({ page }) => {
  const name = unique("dash-cache").slice(0, 40);
  await page.goto("/elasticache");
  await submit(page, "create-cache", { engine: "valkey", mode: "serverless", name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("Serverless");

  // Its name is now taken: the form says so and offers the next free one.
  const { field, input } = await openSheet(page);
  await input("name").fill(name);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(field("name").getByRole("button", { name: /Use / })).toContainText(`${name.slice(0, 38)}-2`);
});

test("ElastiCache: names and node types are repaired in place", async ({ page }) => {
  const { field, input } = await openSheet(page);

  // Identifiers start with a letter and use single hyphens.
  const base = unique("orders cache");
  await input("name").fill(`9 ${base}`);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  const fix = field("name").getByRole("button", { name: /Start with a letter/ });
  await expect(fix).toContainText(base.replace(/\s+/g, "-"));
  await fix.click();
  await expect(input("name")).toHaveValue(base.replace(/\s+/g, "-"));
  await expect(field("name")).not.toHaveAttribute("data-invalid");

  // A mistyped node type suggests the one the region offers.
  await input("nodeType").fill("cache.t4g.mikro");
  await input("nodeType").blur();
  await expect(field("nodeType")).toHaveAttribute("data-invalid", "enum");
  await field("nodeType").getByRole("button", { name: /Did you mean cache\.t4g\.micro/ }).click();
  await expect(input("nodeType")).toHaveValue("cache.t4g.micro");
  await expect(field("nodeType")).not.toHaveAttribute("data-invalid");
});

test("ElastiCache: too many nodes for one shard land on the field with a fix", async ({ page }) => {
  const { form, field, input } = await openSheet(page);
  await form.locator('select[name="mode"]').selectOption("nodes");
  await input("name").fill(unique("dash-shard").slice(0, 40));
  await input("nodes").fill("9");
  await form.locator('button[type="submit"]').click();
  await expect(field("nodes")).toHaveAttribute("data-invalid", "range");
  await expect(form.locator(".result.error")).toHaveCount(0);
  await field("nodes").getByRole("button", { name: /maximum, 6/ }).click();
  await expect(input("nodes")).toHaveValue("6");
  await expect(field("nodes")).not.toHaveAttribute("data-invalid");
});
