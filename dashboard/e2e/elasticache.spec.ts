import { expect, test, type Page } from "@playwright/test";

import { row, submit, unique } from "./helpers";

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

/** Open the create sheet on an engine and deployment tile. */
async function pick(page: Page, engine: string, mode: string) {
  const { form } = await openSheet(page);
  await form.getByTestId(`preset-${engine}`).click();
  await form.getByTestId(`mode-${mode}`).click();
}

test("ElastiCache: create a serverless Valkey cache", async ({ page }) => {
  const name = unique("dash-cache").slice(0, 40);
  // The sheet opens on Valkey, serverless: a name is all it needs.
  const sheet = await openSheet(page);
  await expect(sheet.form.getByTestId("preset-valkey")).toHaveAttribute("aria-checked", "true");
  await expect(sheet.form.getByTestId("mode-serverless")).toHaveAttribute("aria-checked", "true");
  await submit(page, "create-cache", { name });
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
  const { form, field, input } = await openSheet(page);

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

  // A mistyped node type suggests the one the region offers (node-based
  // caches only: serverless ones have no node type).
  await expect(input("nodeType")).toHaveCount(0);
  await form.getByTestId("mode-nodes").click();
  await input("nodeType").fill("cache.t4g.mikro");
  await input("nodeType").blur();
  await expect(field("nodeType")).toHaveAttribute("data-invalid", "enum");
  await field("nodeType").getByRole("button", { name: /Did you mean cache\.t4g\.micro/ }).click();
  await expect(input("nodeType")).toHaveValue("cache.t4g.micro");
  await expect(field("nodeType")).not.toHaveAttribute("data-invalid");
});

test("ElastiCache: too many nodes for one shard land on the field with a fix", async ({ page }) => {
  const { form, field, input } = await openSheet(page);
  await form.getByTestId("mode-nodes").click();
  await input("name").fill(unique("dash-shard").slice(0, 40));
  await input("nodes").fill("9");
  await form.locator('button[type="submit"]').click();
  await expect(field("nodes")).toHaveAttribute("data-invalid", "range");
  await expect(form.locator(".result.error")).toHaveCount(0);
  await field("nodes").getByRole("button", { name: /maximum, 6/ }).click();
  await expect(input("nodes")).toHaveValue("6");
  await expect(field("nodes")).not.toHaveAttribute("data-invalid");
});

test("ElastiCache: a cluster-mode group shows its shards, version and the -c connection command", async ({ page }) => {
  test.setTimeout(180_000);
  const name = unique("dash-shards").slice(0, 40);
  await (await openSheet(page)).form.getByTestId("mode-nodes").click();
  await submit(page, "create-cache", { name, nodes: "2", clusterMode: "on", shards: "2" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".specs")).toContainText(/valkey \d/);
  await expect(page.locator(".specs")).toContainText("2 shards");
  await expect(page.getByLabel("Connection command")).toContainText(" -c");
  // Nodes are grouped by shard (AWS reports no roles in cluster mode).
  await expect(page.getByRole("heading", { level: 2, name: /^Shard / })).toHaveCount(2);
});

test("ElastiCache: snapshot a cache, restore it, and modify the copy", async ({ page }) => {
  test.setTimeout(180_000);
  const name = unique("dash-snap").slice(0, 34);
  await pick(page, "redis", "nodes");
  await submit(page, "create-cache", { name, nodes: "2" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator("li.row").filter({ hasText: "replica" })).toHaveCount(1);

  const snap = `${name}-s1`;
  await submit(page, "take-cache-snapshot", { snapshot: snap });
  await page.goto("/elasticache?tab=snapshots");
  await expect(row(page, snap)).toContainText("available");
  const copy = `${name}-r`;
  await submit(page, `restore-${snap}`, { name: copy });
  await expect(page.getByRole("heading", { level: 1, name: copy })).toBeVisible();

  // Modify: backups kept for 5 days.
  await submit(page, "modify-cache", { retention: "5" });
  await page.getByRole("link", { name: "Maintenance and backups" }).click();
  await expect(page.locator("main")).toContainText("5 days");

  // Resize: one more replica.
  await submit(page, "resize-cache", { replicas: "2" });
  await page.getByRole("link", { name: "Nodes", exact: true }).click();
  await expect(page.locator("li.row").filter({ hasText: "replica" })).toHaveCount(2);
});

test("ElastiCache: Memcached clusters are listed with their nodes", async ({ page }) => {
  const name = unique("dash-mc").slice(0, 40);
  await pick(page, "memcached", "nodes");
  await submit(page, "create-cache", { name, nodes: "2" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.getByLabel("Connection command")).toContainText("telnet");
  await expect(page.getByLabel("Nodes", { exact: true }).locator("li.row")).toHaveCount(2);
  await page.goto("/elasticache");
  await expect(row(page, name)).toContainText("2 × cache.t4g.micro");
});
