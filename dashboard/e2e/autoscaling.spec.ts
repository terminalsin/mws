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

test("Auto Scaling: a group is created in a chosen VPC and its hooks, schedules, warm pool, tags and refreshes are managed", async ({ page }) => {
  const template = unique("dash-lt");
  const group = unique("dash-asg-net");
  await page.goto("/autoscaling");
  await submit(page, "create-launch-template", { name: template });
  const { form, input } = await openSheet(page, "create-group");
  await input("name").fill(group);
  await form.locator('select[name="template"]').selectOption(template);
  await input("min").fill("0");
  await input("desired").fill("0");
  await input("max").fill("2");
  // Network, health checks and tags wait under More.
  await form.locator(".more-fields > summary").click();
  const subnets = form.locator('input[name="subnet"]');
  await expect(subnets.first()).toBeVisible();
  // Only the first subnet.
  const count = await subnets.count();
  for (let i = 1; i < count; i++) await subnets.nth(i).uncheck();
  const subnet = await subnets.first().getAttribute("value");
  await input("health").selectOption("ELB");
  await input("tags").fill(`team=${group}`);
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: group })).toBeVisible();
  await expect(page.locator(".specs")).toContainText(subnet!);
  await expect(page.locator(".specs")).toContainText("ELB");

  // Lifecycle hook and warm pool on the instance management tab.
  await submit(page, "add-hook", { hook: "launch-hook", timeout: "120" });
  await expect(page.getByLabel("Lifecycle hooks")).toContainText("launch-hook");
  await submit(page, "warm-pool", { min: "0", state: "Stopped" });
  await expect(page.locator(".section").filter({ hasText: "Warm pool" })).toContainText("Stopped");

  // A scheduled action and a step policy on automatic scaling.
  await page.getByRole("link", { name: /^Automatic scaling/ }).click();
  await submit(page, "add-schedule", { action: "nightly", desired: "1", kind: "cron", recurrence: "0 2 * * *" });
  await expect(page.getByLabel("Scheduled actions")).toContainText("0 2 * * *");
  // The policy form opens on common policies: pick step scaling.
  const policy = await openSheet(page, "add-policy");
  await policy.form.getByTestId("policy-preset-step").click();
  await submit(page, "add-policy", { policy: "step-out", steps: "0:=1" });
  await expect(page.getByLabel("Scaling policies")).toContainText("step-out");

  // Details: a tag, a suspended process.
  await page.getByRole("link", { name: /^Details/ }).click();
  await expect(page.getByLabel("Tags")).toContainText(group);
  await submit(page, "add-tag", { key: "env", value: "test" });
  await expect(page.getByLabel("Tags")).toContainText("env");
  await page.getByRole("button", { name: "Suspend AZRebalance" }).click();
  await expect(page.getByRole("button", { name: "Resume AZRebalance" })).toBeVisible();

  // Instance refresh with preferences shows in the refresh list.
  await page.getByRole("link", { name: /^Instance refresh/ }).click();
  await submit(page, "start-refresh", { minHealthy: "50", warmup: "0", skipMatching: "on" });
  await expect(page.getByLabel("Instance refreshes").locator("li.row")).toHaveCount(1);
  await expect(page.getByLabel("Instance refreshes")).toContainText("min 50%");
});

test("Auto Scaling: instances go to standby, get protected and come back", async ({ page }) => {
  const template = unique("dash-lt");
  const group = unique("dash-asg-sb");
  await page.goto("/autoscaling");
  await submit(page, "create-launch-template", { name: template });
  await submit(page, "create-group", { name: group, template, min: "0", desired: "1", max: "2" });
  await expect(page.getByRole("heading", { level: 1, name: group })).toBeVisible();
  const instance = page.getByLabel("Instances").locator("li.row").first();
  await expect(instance).toContainText("in service", { timeout: 60_000 });
  const id = (await instance.locator(".row-title").textContent())!.trim();
  await page.getByRole("button", { name: `Protect ${id} from scale in` }).click();
  await expect(instance).toContainText("protected");
  await page.getByRole("button", { name: `Set ${id} to standby` }).click();
  await expect(instance).toContainText("standby");
  await page.getByRole("button", { name: `Return ${id} to service` }).click();
  await expect(instance).toContainText(/pending|in service/);
});
