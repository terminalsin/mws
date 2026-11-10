import { CreateActionTargetCommand, SecurityHubClient } from "@aws-sdk/client-securityhub";
import { expect, test, type Page } from "@playwright/test";

import { enableOnce, row, sdk, unique } from "./helpers";

// Security Hub's forms validate in place: insights suggest the finding
// attribute meant, custom actions reshape names and ids to AWS's limits, and
// automation rule orders clamp to 1-1000.

async function open(page: Page, tab: string, testId: string) {
  await page.goto(`/securityhub?tab=${tab}`);
  await enableOnce(page, "enable-security-hub", `${testId}-open`);
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, input: (name: string) => form.locator(`[name="${name}"]`) };
}

test("Security Hub: an insight's group-by suggests the attribute meant", async ({ page }) => {
  const { form, field, input } = await open(page, "insights", "create-insight");
  const name = unique("dash-insight");
  await input("name").fill(name);
  await input("group").fill("resource id");
  await input("group").blur();
  await expect(field("group")).toHaveAttribute("data-invalid", "enum");
  await field("group").getByRole("button", { name: /Did you mean ResourceId/ }).click();
  await expect(input("group")).toHaveValue("ResourceId");
  await expect(field("group")).not.toHaveAttribute("data-invalid");
  await input("severity").selectOption("HIGH");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, name)).toContainText("ResourceId");
});

test("Security Hub: custom action names and ids are reshaped to fit", async ({ page }) => {
  const { form, field, input } = await open(page, "actions", "create-action");
  // Too long for a custom action name: shorten it in one click.
  await input("name").fill("Send to ticketing queue");
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "tooLong");
  await field("name").getByRole("button").first().click();
  await expect(field("name")).not.toHaveAttribute("data-invalid");
  expect((await input("name").inputValue()).length).toBeLessThanOrEqual(20);

  // Ids are letters and digits only.
  const id = `dash${Date.now().toString(36)}`;
  await input("id").fill(`${id.slice(0, 4)}-${id.slice(4)}`);
  await input("id").blur();
  await expect(field("id")).toHaveAttribute("data-invalid", "pattern");
  await field("id").getByRole("button").first().click();
  await expect(input("id")).toHaveValue(id);

  // Created by someone else meanwhile: the conflict lands on the id, with
  // the next free one.
  await new SecurityHubClient(sdk).send(new CreateActionTargetCommand({ Name: "Taken", Description: "Taken", Id: id }));
  await form.locator('button[type="submit"]').click();
  await expect(field("id")).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("id").getByRole("button", { name: /Use / }).click();
  await expect(input("id")).toHaveValue(`${id}2`);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, `${id}2`)).toBeVisible();
});

test("Security Hub: automation rule order clamps to its range", async ({ page }) => {
  const { form, field, input } = await open(page, "rules", "create-rule");
  const name = unique("dash-rule");
  await input("name").fill(name);
  await input("order").fill("0");
  await input("order").blur();
  await expect(field("order")).toHaveAttribute("data-invalid", "range");
  await field("order").getByRole("button").first().click();
  await expect(input("order")).toHaveValue("1");
  await input("severity").selectOption("LOW");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, name)).toBeVisible();
});
