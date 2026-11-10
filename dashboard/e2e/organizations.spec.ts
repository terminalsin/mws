import { expect, test } from "@playwright/test";

import { enableOnce, submit, unique } from "./helpers";

test("Organizations: an OU appears in the account tree", async ({ page }) => {
  await page.goto("/organizations");
  await enableOnce(page, "create-organization", "create-ou");
  const ou = unique("Dash OU");
  await submit(page, "create-ou", { name: ou });
  await expect(page.getByLabel("Organization structure")).toContainText(ou);
});
