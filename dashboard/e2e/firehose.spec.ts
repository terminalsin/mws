import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("Firehose: a stream with its bucket and role made automatically", async ({ page }) => {
  const name = unique("dash-fh");
  await page.goto("/firehose");
  const form = page.locator("dialog[open]").getByTestId("create-delivery-stream").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("create-delivery-stream-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  await form.locator('[name="name"]').fill(name);
  for (const pick of ["destination-bucket", "firehose-role"]) await form.getByTestId(pick).getByRole("button", { name: "Create automatically" }).click();
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator("main")).toContainText(/firehose-\d{12}-/);
});
