import { GetRoleCommand, IAMClient } from "@aws-sdk/client-iam";
import { expect, test } from "@playwright/test";

import { sdk, submit, unique } from "./helpers";

test("EKS: create a cluster with its service role made automatically", async ({ page }) => {
  const name = unique("dash-eks");
  await page.goto("/eks");
  const form = page.locator("dialog[open]").getByTestId("create-eks-cluster").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("create-eks-cluster-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  await form.locator('[name="name"]').fill(name);
  await form.getByTestId("cluster-role").getByRole("button", { name: "Create automatically" }).click();
  await expect(form.getByTestId("cluster-role-auto")).toContainText("AmazonEKSClusterRole");
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const role = await new IAMClient(sdk).send(new GetRoleCommand({ RoleName: "AmazonEKSClusterRole" }));
  expect(decodeURIComponent(role.Role!.AssumeRolePolicyDocument!)).toContain("eks.amazonaws.com");
});
