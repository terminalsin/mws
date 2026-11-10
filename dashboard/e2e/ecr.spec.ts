import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("ECR: create a repository with a lifecycle rule", async ({ page }) => {
  const name = unique("dash/app");
  await page.goto("/ecr");
  await submit(page, "create-repository", { name, keep: "10" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("Keep the last 10 images");
  await expect(page.locator("pre[aria-label='Push commands']")).toContainText("docker push");
});
