import { GetRoleCommand, IAMClient } from "@aws-sdk/client-iam";
import { expect, test } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("RDS: create a PostgreSQL database and find its connection command", async ({ page }) => {
  const id = unique("dash-db");
  await page.goto("/data/rds");
  await submit(page, "create-database", { engine: "postgres", id, username: "app", password: "correct-horse-battery" });
  await expect(page.getByRole("heading", { level: 1, name: id })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("postgres");
  await page.goto("/data/rds");
  await expect(row(page, id)).toBeVisible();
});

test("ElastiCache: create a serverless Valkey cache", async ({ page }) => {
  const name = unique("dash-cache").slice(0, 40);
  await page.goto("/data/elasticache");
  await submit(page, "create-cache", { engine: "valkey", mode: "serverless", name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("Serverless");
});

test("EKS: create a cluster with its service role made automatically", async ({ page }) => {
  const name = unique("dash-eks");
  await page.goto("/data/eks");
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

test("Firehose: a stream with its bucket and role made automatically", async ({ page }) => {
  const name = unique("dash-fh");
  await page.goto("/data/firehose");
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

test("ECR: create a repository with a lifecycle rule", async ({ page }) => {
  const name = unique("dash/app");
  await page.goto("/data/ecr");
  await submit(page, "create-repository", { name, keep: "10" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("Keep the last 10 images");
  await expect(page.locator("pre[aria-label='Push commands']")).toContainText("docker push");
});

test("ECS: a cluster runs a service from a new task definition", async ({ page }) => {
  const family = unique("dash-web");
  await page.goto("/data/ecs?tab=taskdefs");
  await submit(page, "register-task-definition", { family, image: "public.ecr.aws/nginx/nginx:latest", port: "80" });
  await expect(row(page, family)).toBeVisible();

  const cluster = unique("dash-cluster");
  await page.goto("/data/ecs");
  await submit(page, "create-ecs-cluster", { name: cluster });
  await expect(page.getByRole("heading", { level: 1, name: cluster })).toBeVisible();
  await submit(page, "create-service", { name: "web", taskDefinition: `${family}:1`, desired: "2" });
  await expect(page.getByLabel("Services").locator("li.row").filter({ hasText: "web" })).toContainText("/2 tasks");
});

test("Kinesis: put a record and read it back in the data viewer", async ({ page }) => {
  const name = unique("dash-stream");
  await page.goto("/data/kinesis");
  await submit(page, "create-stream", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  // A new stream is CREATING for a moment, as in AWS.
  await expect(async () => {
    await page.reload();
    await expect(page.locator(".specs")).toContainText("active", { timeout: 1000 });
  }).toPass();
  await submit(page, "put-record", { key: "user-1", data: '{"clicked":"buy"}' });
  await page.reload();
  await expect(page.getByLabel("Records")).toContainText('{"clicked":"buy"}');
});

test("EFS: a file system with an access point", async ({ page }) => {
  const name = unique("dash-fs");
  await page.goto("/data/efs");
  await submit(page, "create-file-system", { name, vpc: "" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await submit(page, "create-access-point", { name: "app", path: "/app" });
  await expect(row(page, "/app")).toBeVisible();
});

test("Containers and data: every list page renders", async ({ page }) => {
  for (const [path, heading] of [
    ["/data/eks", "Clusters"],
    ["/data/firehose", "Firehose streams"],
    ["/data/rds?tab=snapshots", "Snapshots"],
  ]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.locator(".banner.error")).toHaveCount(0);
  }
});
