import { GetRoleCommand, IAMClient } from "@aws-sdk/client-iam";
import { expect, test, type Page } from "@playwright/test";

import { sdk, unique } from "./helpers";

async function openSheet(page: Page, path: string, testId: string) {
  await page.goto(path);
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, input: (name: string) => form.locator(`[name="${name}"]`) };
}

let cluster = "";

test("EKS: create a cluster with its service role made automatically", async ({ page }) => {
  const name = unique("dash-eks");
  const { form, field, input } = await openSheet(page, "/eks", "create-eks-cluster");

  // A name EKS would reject is repaired in place.
  await input("name").fill(name.replace("dash-eks", "dash eks"));
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /Replace spaces/ }).click();
  await expect(input("name")).toHaveValue(name);
  await expect(field("name")).not.toHaveAttribute("data-invalid");

  // Versions come from EKS itself.
  await expect(input("version").locator("option")).not.toHaveCount(1);

  await form.getByTestId("cluster-role").getByRole("button", { name: "Create automatically" }).click();
  await expect(form.getByTestId("cluster-role-auto")).toContainText("AmazonEKSClusterRole");
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const role = await new IAMClient(sdk).send(new GetRoleCommand({ RoleName: "AmazonEKSClusterRole" }));
  expect(decodeURIComponent(role.Role!.AssumeRolePolicyDocument!)).toContain("eks.amazonaws.com");
  cluster = name;

  // The name is now taken: the next free one is offered.
  const again = await openSheet(page, "/eks", "create-eks-cluster");
  await again.input("name").fill(name);
  await again.input("name").blur();
  await expect(again.field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(again.field("name").getByRole("button", { name: /Use / })).toContainText(`${name}-2`);
});

test("EKS: node group fields check each other and EKS's limits", async ({ page }) => {
  test.skip(!cluster, "needs the cluster from the previous test");
  const { form, field, input } = await openSheet(page, `/eks/cluster?name=${encodeURIComponent(cluster)}`, "create-nodegroup");

  // An instance type EC2 doesn't offer gets the close ones.
  await input("type").fill("t3.medum");
  await input("type").blur();
  await expect(field("type")).toHaveAttribute("data-invalid", "enum");
  await field("type").getByRole("button", { name: /t3\.medium/ }).click();
  await expect(input("type")).toHaveValue("t3.medium");

  // Desired can't pass max: clamped to it.
  await input("size").fill("5");
  await input("size").blur();
  await expect(field("size")).toHaveAttribute("data-invalid", "range");
  await field("size").getByRole("button", { name: /^.*: 3$/ }).click();
  await expect(input("size")).toHaveValue("3");
  await expect(field("size")).not.toHaveAttribute("data-invalid");

  // Over EKS's nodes-per-group quota: MWS rejects it, and the rejection
  // lands on the max field with a value inside the limit.
  await input("name").fill(unique("ng"));
  await form.getByTestId("node-role").getByRole("button", { name: "Create automatically" }).click();
  await input("max").fill("100000");
  await form.locator('button[type="submit"]').click();
  await expect(field("max")).toHaveAttribute("data-invalid", "range");
  await expect(form.locator(".result.error")).toHaveCount(0);
  await field("max").locator(".repair").first().click();
  expect(Number(await input("max").inputValue())).toBeLessThan(100000);
  await expect(field("max")).not.toHaveAttribute("data-invalid");
});
