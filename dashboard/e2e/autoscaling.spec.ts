import { expect, test, type Page } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("Auto Scaling: a group launches its desired capacity", async ({ page }) => {
  const template = unique("dash-lt");
  const group = unique("dash-asg");
  await page.goto("/autoscaling");
  await submit(page, "create-launch-template", { name: template });
  await submit(page, "create-group", { name: group, template, min: "0", desired: "1", max: "3" });
  await expect(page.getByRole("heading", { level: 1, name: group })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Instances").locator("li.row")).toHaveCount(1, { timeout: 1000 });
  }).toPass();
  await page.getByRole("button", { name: "Scale out" }).click();
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Instances").locator("li.row")).toHaveCount(2, { timeout: 1000 });
  }).toPass();
  await page.getByRole("link", { name: /^Activity/ }).click();
  await expect(page.getByLabel("Activity").locator("li.row").first()).toContainText(/Launching/);
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, input: (name: string) => form.locator(`[name="${name}"]`) };
}

test("Auto Scaling: forms repair names, instance types and sizes in place", async ({ page }) => {
  const template = unique("dash-lt");
  await page.goto("/autoscaling");
  await submit(page, "create-launch-template", { name: template });

  // Launch template: spaces are not allowed, a taken name offers the next
  // free one, and a mistyped instance type offers the real one.
  let { field, input } = await openSheet(page, "create-launch-template");
  await input("name").fill("web servers");
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /web-servers/ }).click();
  await expect(input("name")).toHaveValue("web-servers");
  await input("name").fill(template);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(field("name").getByRole("button", { name: /Use / })).toContainText(`${template}-2`);
  await input("type").fill("t3.mcro");
  await input("type").blur();
  await expect(field("type")).toHaveAttribute("data-invalid", "enum");
  await field("type").getByRole("button", { name: /t3\.micro$/ }).click();
  await expect(input("type")).toHaveValue("t3.micro");
  await expect(field("type")).not.toHaveAttribute("data-invalid");
  await page.keyboard.press("Escape");

  // Group size: desired and max follow the min as it changes.
  ({ field, input } = await openSheet(page, "create-group"));
  await input("min").fill("3");
  await input("desired").fill("1");
  await input("desired").blur();
  await expect(field("desired")).toHaveAttribute("data-invalid", "range");
  await expect(field("max")).not.toHaveAttribute("data-invalid");
  await field("desired").getByRole("button", { name: /Raise to the minimum/ }).click();
  await expect(input("desired")).toHaveValue("3");
  // Max 2 is now below the min: submitting is blocked on the max field.
  await input("name").fill(unique("dash-asg"));
  await page.locator("dialog[open]").locator('button[type="submit"]').click();
  await expect(field("max")).toHaveAttribute("data-invalid", "range");
  await expect(input("max")).toBeFocused();
  await field("max").getByRole("button", { name: /Raise to the minimum/ }).click();
  await expect(input("max")).toHaveValue("3");
  await expect(field("max")).not.toHaveAttribute("data-invalid");
});
