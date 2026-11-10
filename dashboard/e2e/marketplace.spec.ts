import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("Marketplace: subscribe a buyer and meter usage", async ({ page }) => {
  const title = unique("Dash SaaS");
  await page.goto("/marketplace");
  await submit(page, "create-product", { title, dimensions: "users requests" });
  await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
  const subscribed = await submit(page, "subscribe", { account: "111122223333", "dim:users": "10" });
  await expect(subscribed).toContainText("x-amzn-marketplace-token");
  await page.reload();
  await expect(row(page, "111122223333")).toContainText("users 10");
  await submit(page, "meter", { dimension: "users", quantity: "7" });
  await page.reload();
  await expect(page.getByLabel("Usage by dimension")).toContainText("7");
  await page.goto("/marketplace?tab=records");
  await expect(page.locator("li.row").filter({ hasText: title }).first()).toContainText("7 × users");
});
