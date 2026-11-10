import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("CodeArtifact: a repository with an npm upstream and its connection instructions", async ({ page }) => {
  const domain = unique("dash").toLowerCase().slice(0, 40);
  const repo = unique("dash-npm");
  await page.goto("/codeartifact?tab=domains");
  await submit(page, "create-domain", { name: domain });
  await expect(row(page, domain)).toBeVisible();
  await page.goto("/codeartifact");
  await submit(page, "create-repository", { name: repo, domain, external: "public:npmjs" });
  await expect(page.getByRole("heading", { level: 1, name: repo })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("npmjs");
  await expect(page.locator("pre.code")).toContainText("npm config set registry");
  await expect(page.locator("pre.code")).toContainText(`/${domain}-`);
});
