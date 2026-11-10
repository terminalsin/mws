import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("Secrets Manager: create a secret and reveal it", async ({ page }) => {
  const name = unique("dash/secret");
  await page.goto("/secrets");
  await submit(page, "create-secret", { name, value: '{"password":"hunter2"}' });
  await page.getByRole("link", { name }).click();
  await expect(page.getByText("hunter2")).toHaveCount(0);
  await page.getByRole("link", { name: "Reveal value" }).click();
  await expect(page.locator("pre[aria-label='Secret value']")).toContainText("hunter2");
});
