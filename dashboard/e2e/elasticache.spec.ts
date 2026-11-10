import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("ElastiCache: create a serverless Valkey cache", async ({ page }) => {
  const name = unique("dash-cache").slice(0, 40);
  await page.goto("/elasticache");
  await submit(page, "create-cache", { engine: "valkey", mode: "serverless", name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("Serverless");
});
