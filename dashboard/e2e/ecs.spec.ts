import { CreateClusterCommand, CreateServiceCommand, ECSClient, RegisterTaskDefinitionCommand, RunTaskCommand, StopTaskCommand } from "@aws-sdk/client-ecs";
import { DescribeSubnetsCommand, EC2Client } from "@aws-sdk/client-ec2";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("ECS: a cluster runs a service from a new task definition", async ({ page }) => {
  const family = unique("dash-web");
  await page.goto("/ecs?tab=taskdefs");
  await submit(page, "register-task-definition", { family, image: "public.ecr.aws/nginx/nginx:latest", port: "80" });
  await expect(row(page, family)).toBeVisible();

  const cluster = unique("dash-cluster");
  await page.goto("/ecs");
  await submit(page, "create-ecs-cluster", { name: cluster });
  await expect(page.getByRole("heading", { level: 1, name: cluster })).toBeVisible();
  await submit(page, "create-service", { name: "web", taskDefinition: `${family}:1`, desired: "2" });
  await expect(page.getByLabel("Services").locator("li.row").filter({ hasText: "web" })).toContainText("/2 tasks");
});

// Inline validation (see validation.spec.ts): names, images and Fargate
// sizes are checked in the field, with repairs.

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

test("ECS validation: task definitions repair names, images and Fargate sizes", async ({ page }) => {
  const { form, field, input } = await openSheet(page, "/ecs?tab=taskdefs", "register-task-definition");
  const family = unique("Dash Web");
  await input("family").fill(family);
  await input("family").blur();
  await expect(field("family")).toHaveAttribute("data-invalid", "pattern");
  await field("family").getByRole("button", { name: /Replace spaces/ }).click();
  await expect(input("family")).toHaveValue(family.replace(/\s+/g, "-"));

  await input("image").fill("Nginx:Latest");
  await input("image").blur();
  await expect(field("image")).toHaveAttribute("data-invalid", "pattern");
  await field("image").getByRole("button", { name: /Lowercase/ }).click();
  await expect(input("image")).toHaveValue("nginx:latest");

  // 1 vCPU does not come with 0.5 GB: the nearest sizes Fargate offers are
  // suggested.
  await input("cpu").selectOption("1024");
  await expect(field("memory")).toContainText("2–8 GB");
  await form.locator('button[type="submit"]').click();
  await expect(field("memory")).toHaveAttribute("data-invalid", "enum");
  await expect(input("memory")).toBeFocused();
  await field("memory").getByRole("button", { name: "Use 2048" }).click();
  await expect(input("memory")).toHaveValue("2048");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, family.replace(/\s+/g, "-"))).toBeVisible();
});

test("ECS validation: taken cluster and service names suggest the next free one", async ({ page }) => {
  const ecs = new ECSClient(sdk);
  const cluster = unique("dash-taken");
  await ecs.send(new CreateClusterCommand({ clusterName: cluster }));
  let sheet = await openSheet(page, "/ecs", "create-ecs-cluster");
  await sheet.input("name").fill(cluster);
  await sheet.input("name").blur();
  await expect(sheet.field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(sheet.field("name").getByRole("button", { name: /Use / })).toContainText(`${cluster}-2`);

  // A service created after the page loaded: ECS answers "not idempotent",
  // which lands on the name field with the same repair.
  const family = unique("dash-svc");
  await ecs.send(
    new RegisterTaskDefinitionCommand({ family, requiresCompatibilities: ["FARGATE"], networkMode: "awsvpc", cpu: "256", memory: "512", containerDefinitions: [{ name: "web", image: "nginx:latest" }] }),
  );
  sheet = await openSheet(page, `/ecs/cluster?name=${cluster}`, "create-service");
  const subnets = (await new EC2Client(sdk).send(new DescribeSubnetsCommand({ Filters: [{ Name: "default-for-az", Values: ["true"] }] }))).Subnets ?? [];
  await ecs.send(
    new CreateServiceCommand({ cluster, serviceName: "web", taskDefinition: `${family}:1`, desiredCount: 0, launchType: "FARGATE", networkConfiguration: { awsvpcConfiguration: { subnets: [subnets[0].SubnetId!] } } }),
  );
  await sheet.input("name").fill("web");
  await sheet.input("taskDefinition").selectOption(`${family}:1`);
  await sheet.form.locator('button[type="submit"]').click();
  await expect(sheet.field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await sheet.field("name").getByRole("button", { name: /Use / }).click();
  await expect(sheet.input("name")).toHaveValue("web-2");
});

async function seedService(family: string, cluster: string, services: string[] = ["web"], desiredCount = 1) {
  const ecs = new ECSClient(sdk);
  await ecs.send(new CreateClusterCommand({ clusterName: cluster }));
  await ecs.send(
    new RegisterTaskDefinitionCommand({ family, requiresCompatibilities: ["FARGATE"], networkMode: "awsvpc", cpu: "256", memory: "512", containerDefinitions: [{ name: "web", image: "nginx:latest" }] }),
  );
  const subnets = (await new EC2Client(sdk).send(new DescribeSubnetsCommand({ Filters: [{ Name: "default-for-az", Values: ["true"] }] }))).Subnets ?? [];
  for (const serviceName of services) {
    await ecs.send(
      new CreateServiceCommand({ cluster, serviceName, taskDefinition: `${family}:1`, desiredCount, launchType: "FARGATE", networkConfiguration: { awsvpcConfiguration: { subnets: [subnets[0].SubnetId!] } } }),
    );
  }
  return ecs;
}

test("ECS: every service is listed, past DescribeServices' 10 per call", async ({ page }) => {
  const cluster = unique("dash-many");
  const names = Array.from({ length: 12 }, (_, i) => `svc-${String(i + 1).padStart(2, "0")}`);
  await seedService(unique("dash-many"), cluster, names, 0);
  await page.goto(`/ecs/cluster?name=${cluster}`);
  await expect(page.getByLabel("Services").locator("li.row")).toHaveCount(12);
  await expect(page.getByRole("link", { name: /Services\s*12/ })).toBeVisible();
});

test("ECS: deploy a new task definition revision from the service page", async ({ page }) => {
  test.setTimeout(120_000);
  const family = unique("dash-deploy");
  const cluster = unique("dash-deploy");
  const ecs = await seedService(family, cluster);
  await ecs.send(
    new RegisterTaskDefinitionCommand({ family, requiresCompatibilities: ["FARGATE"], networkMode: "awsvpc", cpu: "256", memory: "512", containerDefinitions: [{ name: "web", image: "nginx:1.27" }] }),
  );
  await page.goto(`/ecs/cluster?name=${cluster}`);
  await page.getByLabel("Services").locator("li.row").filter({ hasText: "web" }).locator("a").click();
  await expect(page.getByRole("heading", { level: 1, name: "web" })).toBeVisible();
  await expect(page.locator(".specs")).toContainText(`${family}:1`);
  await expect(page.getByLabel("Current deployments").locator("li.row")).toHaveCount(1);

  await submit(page, "update-service", { taskDefinition: `${family}:2` });
  await expect(page.locator(".specs")).toContainText(`${family}:2`);
  await page.getByRole("link", { name: "Events" }).click();
  await expect(page.getByLabel("Events").locator("li.row").first()).toBeVisible();

  // The same revision again: a forced new deployment.
  await submit(page, "update-service", { force: "on" });
  await page.getByRole("link", { name: /^Deployments/ }).click();
  await expect(page.getByLabel("Deployments").locator("li.row").first()).toBeVisible();
});

test("ECS: stopped tasks stay visible with the reason they stopped", async ({ page }) => {
  const family = unique("dash-stop");
  const cluster = unique("dash-stop");
  const ecs = await seedService(family, cluster, []);
  const subnets = (await new EC2Client(sdk).send(new DescribeSubnetsCommand({ Filters: [{ Name: "default-for-az", Values: ["true"] }] }))).Subnets ?? [];
  const run = await ecs.send(
    new RunTaskCommand({ cluster, taskDefinition: `${family}:1`, launchType: "FARGATE", networkConfiguration: { awsvpcConfiguration: { subnets: [subnets[0].SubnetId!] } } }),
  );
  const arn = run.tasks![0].taskArn!;
  await ecs.send(new StopTaskCommand({ cluster, task: arn, reason: "Scaled down by the e2e test" }));
  await page.goto(`/ecs/cluster?name=${cluster}&tab=tasks&status=STOPPED`);
  const stopped = row(page, arn.split("/").pop()!);
  await expect(stopped).toContainText("Scaled down by the e2e test");
  await stopped.locator("a").click();
  await expect(page.getByTestId("stopped-reason")).toContainText("Scaled down by the e2e test");
  await expect(page.getByTestId("stop-task")).toHaveCount(0);
});

test("ECS: a task definition shows its containers and revisions, and makes a new revision from JSON", async ({ page }) => {
  const family = unique("dash-td");
  // The environment waits under More.
  const { form } = await openSheet(page, "/ecs?tab=taskdefs", "register-task-definition");
  await form.locator("summary", { hasText: "More" }).click();
  await submit(page, "register-task-definition", { family, image: "public.ecr.aws/nginx/nginx:latest", port: "80", env: "MODE=e2e" });
  await row(page, family).locator("a").click();
  await expect(page.getByRole("heading", { level: 1, name: `${family}:1` })).toBeVisible();
  await expect(page.locator("main")).toContainText("MODE=e2e");
  await expect(page.locator("main")).toContainText(`/ecs/${family}`);

  await submit(page, "new-revision");
  await expect(page.getByRole("heading", { level: 1, name: `${family}:2` })).toBeVisible();
  await page.getByRole("link", { name: /^Revisions/ }).click();
  await expect(page.getByLabel("Revisions").locator("li.row")).toHaveCount(2);
});
