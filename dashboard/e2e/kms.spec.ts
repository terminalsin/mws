import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("KMS: create a key and round-trip data through it", async ({ page }) => {
  const alias = unique("dash-key");
  await page.goto("/kms");
  await submit(page, "create-key", { alias });
  await page.getByRole("link", { name: alias }).click();
  const result = await submit(page, "try-key", { plaintext: "round trip" });
  await expect(result).toContainText("→ round trip");
  await submit(page, "schedule-deletion", { days: "7" });
  await expect(page.getByTestId("cancel-deletion")).toBeVisible();
});
