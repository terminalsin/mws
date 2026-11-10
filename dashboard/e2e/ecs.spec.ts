import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

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
