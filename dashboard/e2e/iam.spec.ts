import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("IAM: create a role, attach a managed policy, group roles by who trusts them", async ({ page }) => {
  const role = unique("dash-role");
  await page.goto("/iam?tab=roles");
  await submit(page, "create-role", { name: role });
  await page.getByRole("link", { name: role }).click();
  await expect(page.locator("pre[aria-label='Trust policy']")).toContainText("lambda.amazonaws.com");
  await submit(page, "attach-policy", { policyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" });
  await expect(row(page, "ReadOnlyAccess")).toBeVisible();

  await page.goto("/iam?tab=roles");
  await expect(row(page, role)).toContainText("lambda.amazonaws.com");
});

test("IAM: a user gets an access key, shown once", async ({ page }) => {
  const user = unique("dash-user");
  await page.goto("/iam");
  await submit(page, "create-user", { name: user });
  await page.getByRole("link", { name: user }).click();
  const result = await submit(page, "create-access-key");
  await expect(result).toContainText("AWS_SECRET_ACCESS_KEY=");
});
