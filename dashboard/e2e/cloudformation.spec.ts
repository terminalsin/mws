import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("CloudFormation: create a stack and see its resources and outputs", async ({ page }) => {
  const name = unique("dash-stack");
  await page.goto("/cloudformation");
  await submit(page, "create-stack", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Resources").locator("li.row")).toHaveCount(2, { timeout: 1000 });
  }).toPass();
  await expect(row(page, "Queue")).toContainText("AWS::SQS::Queue");
  await page.getByRole("link", { name: /^Outputs/ }).click();
  await expect(row(page, "QueueUrl")).toContainText(name);
});
