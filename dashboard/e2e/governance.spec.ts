import { expect, test, type Page } from "@playwright/test";

import { row, submit, unique } from "./helpers";

/** Turn a service on if this MWS has not yet: the page then becomes the
 * service's own, so wait for one of its controls instead of a result. */
async function enableOnce(page: Page, enable: string, next: string) {
  await expect(page.getByTestId(enable).or(page.getByTestId(next)).first()).toBeAttached();
  if ((await page.getByTestId(enable).count()) > 0) {
    await expect(async () => {
      if ((await page.getByTestId(enable).count()) > 0) await page.getByTestId(enable).locator('button[type="submit"]').click();
      await expect(page.getByTestId(next).first()).toBeAttached({ timeout: 3000 });
    }).toPass();
  }
}

test("CloudFormation: create a stack and see its resources and outputs", async ({ page }) => {
  const name = unique("dash-stack");
  await page.goto("/governance/cloudformation");
  await submit(page, "create-stack", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Resources").locator("li.row")).toHaveCount(2, { timeout: 1000 });
  }).toPass();
  await expect(row(page, "Queue")).toContainText("AWS::SQS::Queue");
  await page.getByRole("link", { name: /^Outputs/ }).click();
  await expect(row(page, "QueueUrl")).toContainText(name);
});

test("Organizations: an OU appears in the account tree", async ({ page }) => {
  await page.goto("/governance/organizations");
  await enableOnce(page, "create-organization", "create-ou");
  const ou = unique("Dash OU");
  await submit(page, "create-ou", { name: ou });
  await expect(page.getByLabel("Organization structure")).toContainText(ou);
});

test("GuardDuty: sample findings are sorted by severity", async ({ page }) => {
  await page.goto("/governance/guardduty");
  await enableOnce(page, "enable-guardduty", "sample-findings");
  await page.getByRole("button", { name: "Generate sample findings" }).click();
  await expect(page.locator("li.row").first()).toBeVisible();
  // The most severe come first.
  await expect(page.locator(".section-head h2").first()).toHaveText(/High|Critical/);
});

test("Identity Center: add a user and a permission set", async ({ page }) => {
  await page.goto("/governance/identitycenter");
  await enableOnce(page, "enable-identity-center", "create-sso-user");
  const user = unique("dash.user");
  await submit(page, "create-sso-user", { username: user, given: "Dash", family: "Board", email: `${user}@example.com` });
  await expect(row(page, `${user}@example.com`)).toBeVisible();
  await page.goto("/governance/identitycenter?tab=permissionsets");
  const set = unique("ReadOnly").slice(0, 32);
  await submit(page, "create-permission-set", { name: set });
  await expect(row(page, set)).toContainText("ReadOnlyAccess");
});

test("Management and governance: every list page renders", async ({ page }) => {
  for (const [path, heading] of [
    ["/governance/cloudtrail", "Event history"],
    ["/governance/cloudtrail?tab=trails", "Trails"],
    ["/governance/servicequotas", "AWS services"],
    ["/governance/ce", "Cost and usage"],
    ["/governance/ram", "Shared by me"],
    ["/governance/organizations?tab=policies", "Service control policies"],
  ]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.locator(".banner.error")).toHaveCount(0);
  }
});
