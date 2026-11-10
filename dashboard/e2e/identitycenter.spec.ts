import { CreatePermissionSetCommand, ListInstancesCommand, SSOAdminClient } from "@aws-sdk/client-sso-admin";
import { expect, test, type Page } from "@playwright/test";

import { enableOnce, ensureOrganization, row, sdk, submit, unique } from "./helpers";

test("Identity Center: add a user and a permission set", async ({ page }) => {
  await ensureOrganization();
  await page.goto("/identitycenter");
  await enableOnce(page, "enable-identity-center", "create-sso-user");
  const user = unique("dash.user");
  await submit(page, "create-sso-user", { username: user, given: "Dash", family: "Board", email: `${user}@example.com` });
  await expect(row(page, `${user}@example.com`)).toBeVisible();
  await page.goto("/identitycenter?tab=permissionsets");
  const set = unique("ReadOnly").slice(0, 32);
  await submit(page, "create-permission-set", { name: set });
  await expect(row(page, set)).toContainText("ReadOnlyAccess");
});

async function openSheet(page: Page, path: string, testId: string) {
  await page.goto(path);
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const input = (name: string) => form.locator(`[name="${name}"]`);
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, input, field };
}

test("Identity Center: user fields validate in place with repairs", async ({ page }) => {
  await ensureOrganization();
  await page.goto("/identitycenter");
  await enableOnce(page, "enable-identity-center", "create-sso-user");
  const existing = unique("dash.taken");
  await submit(page, "create-sso-user", { username: existing, given: "Dash", family: "Taken" });
  await expect(row(page, existing)).toBeVisible();

  const { input, field } = await openSheet(page, "/identitycenter", "create-sso-user");
  // Spaces are not allowed in a username: one click replaces them.
  await input("username").fill("Dash Board");
  await input("username").blur();
  await expect(field("username")).toHaveAttribute("data-invalid", "pattern");
  await field("username").getByRole("button", { name: /Replace spaces/ }).click();
  await expect(input("username")).toHaveValue("Dash-Board");
  await expect(field("username")).not.toHaveAttribute("data-invalid");

  // The identity store ignores case, so a differently cased name is taken.
  await input("username").fill(existing.toUpperCase());
  await input("username").blur();
  await expect(field("username")).toHaveAttribute("data-invalid", "taken");
  await field("username").getByRole("button", { name: /Use / }).click();
  await expect(input("username")).toHaveValue(`${existing.toUpperCase()}-2`);

  // A mistyped email domain is caught with the likely one.
  await input("email").fill("dash@gmial.com");
  await input("email").blur();
  await expect(field("email")).toHaveAttribute("data-invalid", "format");
  await field("email").getByRole("button", { name: /gmail\.com/ }).click();
  await expect(input("email")).toHaveValue("dash@gmail.com");
});

test("Identity Center: permission set names are fixed in place, server conflicts included", async ({ page }) => {
  await ensureOrganization();
  await page.goto("/identitycenter");
  await enableOnce(page, "enable-identity-center", "create-sso-user");

  let { form, input, field } = await openSheet(page, "/identitycenter?tab=permissionsets", "create-permission-set");
  // Longer than the 32 characters AWS allows: shortened to fit.
  await input("name").fill("ReadOnlyAccessForTheWholeEngineeringOrg");
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "tooLong");
  await field("name").getByRole("button", { name: /Shorten to 32/ }).click();
  expect((await input("name").inputValue()).length).toBeLessThanOrEqual(32);
  await expect(field("name")).not.toHaveAttribute("data-invalid");

  // Created by someone else after the page loaded: MWS answers
  // ConflictException, which lands on the name with the next free name.
  const set = unique("Dash").slice(0, 28);
  ({ form, input, field } = await openSheet(page, "/identitycenter?tab=permissionsets", "create-permission-set"));
  const admin = new SSOAdminClient(sdk);
  const instance = (await admin.send(new ListInstancesCommand({}))).Instances![0].InstanceArn!;
  await admin.send(new CreatePermissionSetCommand({ InstanceArn: instance, Name: set }));
  await input("name").fill(set);
  await form.locator('button[type="submit"]').click();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(input("name")).toHaveValue(`${set}-2`);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, `${set}-2`)).toBeVisible();
});
