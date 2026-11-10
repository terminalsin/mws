import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("Auto Scaling: a group launches its desired capacity", async ({ page }) => {
  const template = unique("dash-lt");
  const group = unique("dash-asg");
  await page.goto("/autoscaling");
  await submit(page, "create-launch-template", { name: template });
  await submit(page, "create-group", { name: group, template, min: "0", desired: "1", max: "3" });
  await expect(page.getByRole("heading", { level: 1, name: group })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Instances").locator("li.row")).toHaveCount(1, { timeout: 1000 });
  }).toPass();
  await page.getByRole("button", { name: "Scale out" }).click();
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Instances").locator("li.row")).toHaveCount(2, { timeout: 1000 });
  }).toPass();
  await page.getByRole("link", { name: /^Activity/ }).click();
  await expect(page.getByLabel("Activity").locator("li.row").first()).toContainText(/Launching/);
});
