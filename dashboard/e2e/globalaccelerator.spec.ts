import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("Global Accelerator: create an accelerator with a listener", async ({ page }) => {
  const name = unique("dash-ga");
  await page.goto("/ga");
  await submit(page, "create-accelerator", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await submit(page, "add-ga-listener", { ports: "443" });
  await expect(page.getByRole("heading", { name: "TCP 443" })).toBeVisible();
});
