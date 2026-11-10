import { DescribeSubnetsCommand, EC2Client } from "@aws-sdk/client-ec2";
import { CreateClusterCommand, CreateNodegroupCommand, DescribeClusterCommand, DescribeNodegroupCommand, EKSClient, ListFargateProfilesCommand, UpdateClusterVersionCommand } from "@aws-sdk/client-eks";
import { CreateRoleCommand, GetRoleCommand, IAMClient } from "@aws-sdk/client-iam";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

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
  const { form, field, input } = await openSheet(page, `/eks/cluster?name=${encodeURIComponent(cluster)}&tab=compute`, "create-nodegroup");

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

/** A role EKS (and its nodes) may assume, made once. */
async function seedRole() {
  const iam = new IAMClient(sdk);
  const RoleName = "dash-e2e-eks-role";
  const doc = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: ["eks.amazonaws.com", "ec2.amazonaws.com"] }, Action: "sts:AssumeRole" }] });
  return (await iam.send(new GetRoleCommand({ RoleName })).catch(() => iam.send(new CreateRoleCommand({ RoleName, AssumeRolePolicyDocument: doc })))).Role!.Arn!;
}

async function seedCluster(version: string) {
  const eks = new EKSClient(sdk);
  const roleArn = await seedRole();
  const subnets = ((await new EC2Client(sdk).send(new DescribeSubnetsCommand({ Filters: [{ Name: "default-for-az", Values: ["true"] }] }))).Subnets ?? []).map((s) => s.SubnetId!);
  const name = unique("dash-eks");
  await eks.send(new CreateClusterCommand({ name, version, roleArn, resourcesVpcConfig: { subnetIds: subnets }, accessConfig: { authenticationMode: "API_AND_CONFIG_MAP" } }));
  await expect.poll(async () => (await eks.send(new DescribeClusterCommand({ name }))).cluster?.status, { timeout: 60_000 }).toBe("ACTIVE");
  return { eks, name, roleArn, subnets };
}

test("EKS: upgrade a cluster one minor version and follow the update", async ({ page }) => {
  test.setTimeout(120_000);
  const { name } = await seedCluster("1.33");
  await page.goto(`/eks/cluster?name=${name}`);
  await submit(page, "upgrade-cluster", { version: "1.34" });
  await page.getByRole("link", { name: "Update history" }).click();
  await expect(page.getByLabel("Updates").locator("li.row").first()).toContainText("Version update: Version 1.34");
  await expect(page.locator(".specs")).toContainText("1.34");
});

test("EKS: a node group page links its Auto Scaling group and upgrades it to the cluster's version", async ({ page }) => {
  test.setTimeout(180_000);
  const { eks, name, roleArn, subnets } = await seedCluster("1.33");
  const nodegroupName = unique("ng");
  await eks.send(new CreateNodegroupCommand({ clusterName: name, nodegroupName, nodeRole: roleArn, subnets, scalingConfig: { minSize: 1, desiredSize: 1, maxSize: 2 } }));
  await expect.poll(async () => (await eks.send(new DescribeNodegroupCommand({ clusterName: name, nodegroupName }))).nodegroup?.status, { timeout: 90_000 }).toBe("ACTIVE");
  await eks.send(new UpdateClusterVersionCommand({ name, version: "1.34" }));
  await expect.poll(async () => (await eks.send(new DescribeClusterCommand({ name }))).cluster?.status, { timeout: 90_000 }).toBe("ACTIVE");

  await page.goto(`/eks/cluster?name=${name}&tab=compute`);
  await row(page, nodegroupName).locator("a").click();
  await expect(page.getByRole("heading", { level: 1, name: nodegroupName })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("1.33 (cluster 1.34)");
  await expect(page.getByLabel("Auto Scaling groups").locator("a").first()).toHaveAttribute("href", /\/autoscaling\/group\?name=/);

  await submit(page, "upgrade-nodegroup");
  await page.getByRole("link", { name: /^Update history/ }).click();
  await expect(page.getByLabel("Updates").locator("li.row").first()).toContainText("Version 1.34");
});

test("EKS: Fargate profiles, add-ons and access entries, then the cluster deletes", async ({ page }) => {
  test.setTimeout(180_000);
  const { name, roleArn } = await seedCluster("1.34");

  // Fargate: a profile with its pod execution role made automatically.
  await page.goto(`/eks/cluster?name=${name}&tab=compute`);
  await submit(page, "create-fargate-profile", { name: "default-ns", namespace: "default" });
  await expect(page.getByLabel("Fargate profiles").locator("li.row").filter({ hasText: "default-ns" })).toBeVisible();

  // Add-ons: the first one EKS offers, with its status.
  await page.goto(`/eks/cluster?name=${name}&tab=addons`);
  await submit(page, "create-addon");
  await expect(page.getByLabel("Add-ons").locator("li.row")).toHaveCount(1);

  // Access: a role gets the view policy.
  await page.goto(`/eks/cluster?name=${name}&tab=access`);
  await submit(page, "create-access-entry", { principal: roleArn, policy: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy" });
  await expect(page.getByLabel("Access entries").locator("li.row").filter({ hasText: "dash-e2e-eks-role" })).toContainText("AmazonEKSViewPolicy");

  // A cluster with a Fargate profile can't be deleted: delete the profile, then the cluster.
  await page.goto(`/eks/cluster?name=${name}&tab=compute`);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByLabel("Fargate profiles").locator("li.row").filter({ hasText: "default-ns" }).getByRole("button", { name: /Delete/ }).click();
  const eks = new EKSClient(sdk);
  await expect.poll(async () => (await eks.send(new ListFargateProfilesCommand({ clusterName: name }))).fargateProfileNames?.length, { timeout: 60_000 }).toBe(0);
  await page.goto(`/eks/cluster?name=${name}`);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-eks-cluster").locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/\/eks$/);
});
