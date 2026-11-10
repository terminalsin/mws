import { expect, test } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("Amplify: deploy a site to a branch", async ({ page, request }) => {
  const name = unique("dash-site");
  await page.goto("/amplify");
  await submit(page, "create-app", { name, branch: "main" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const appId = new URL(page.url()).searchParams.get("id")!;
  await row(page, "main").getByRole("link").first().click();
  await submit(page, "deploy", { html: `<h1>${name}</h1>` });
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Deployments").locator("li.row").first()).toContainText("succeed", { timeout: 1000 });
  }).toPass();
  const site = await request.get(`${sdk.endpoint}/_aws/amplify/sites/${appId}/main/`);
  expect(await site.text()).toContain(name);
});
