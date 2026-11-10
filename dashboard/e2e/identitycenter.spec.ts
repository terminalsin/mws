import { expect, test } from "@playwright/test";

import { enableOnce, ensureOrganization, row, submit, unique } from "./helpers";

test("Identity Center: add a user and a permission set", async ({ page }) => {
  await ensureOrganization();
  await page.goto("/identitycenter");
  await enableOnce(page, "enable-identity-center", "create-sso-user");
  const user = unique("dash.user");
  await submit(page, "create-sso-user", { username: user, given: "Dash", family: "Board", email: `${user}@example.com` });
  await expect(row(page, `${user}@example.com`)).toBeVisible();
  await page.goto("/identitycenter?tab=permissionsets");
  const set = unique("ReadOnly").slice(0, 32);
  await submit(page, "create-permission-set", { name: set });
  await expect(row(page, set)).toContainText("ReadOnlyAccess");
});
