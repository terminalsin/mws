import { expect, test } from "@playwright/test";

import { ensureOrganization } from "./helpers";

test("Containers and data: every list page renders", async ({ page }) => {
  for (const [path, heading] of [
    ["/eks", "Clusters"],
    ["/firehose", "Firehose streams"],
    ["/rds?tab=snapshots", "Snapshots"],
  ]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.locator(".banner.error")).toHaveCount(0);
  }
});

test("Management and governance: every list page renders", async ({ page }) => {
  await ensureOrganization();
  for (const [path, heading] of [
    ["/cloudtrail", "Event history"],
    ["/cloudtrail?tab=trails", "Trails"],
    ["/servicequotas", "AWS services"],
    ["/ce", "Cost and usage"],
    ["/ram", "Shared by me"],
    ["/organizations?tab=policies", "Service control policies"],
  ]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.locator(".banner.error")).toHaveCount(0);
  }
});

test("AI and developer tools: every list page renders", async ({ page }) => {
  for (const [path, heading] of [
    ["/bedrock/profiles", "Inference profiles"],
    ["/bedrock/profiles?tab=application", "Inference profiles"],
    ["/bedrock/settings", "Settings"],
    ["/codeartifact?tab=domains", "Domains"],
    ["/imagebuilder?tab=images", "Images"],
    ["/autoscaling", "Auto Scaling groups"],
  ]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.locator(".banner.error")).toHaveCount(0);
  }
});
