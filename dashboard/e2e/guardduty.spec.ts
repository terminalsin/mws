import { expect, test } from "@playwright/test";

import { enableOnce, row } from "./helpers";

test("GuardDuty: sample findings are sorted by severity", async ({ page }) => {
  await page.goto("/guardduty");
  await enableOnce(page, "enable-guardduty", "sample-findings");
  await page.getByRole("button", { name: "Generate sample findings" }).click();
  await expect(page.locator("li.row").first()).toBeVisible();
  // The most severe come first.
  await expect(page.locator(".section-head h2").first()).toHaveText(/High|Critical/);
});
