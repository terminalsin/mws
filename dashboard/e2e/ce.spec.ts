import { CostExplorerClient, CreateCostCategoryDefinitionCommand } from "@aws-sdk/client-cost-explorer";
import { CreateTopicCommand, SNSClient } from "@aws-sdk/client-sns";
import { expect, test, type Page } from "@playwright/test";

import { sdk, unique } from "./helpers";

// Cost Explorer's forms: monitors, alert subscriptions and cost categories,
// with problems shown in their fields and one-click repairs.

async function openSheet(page: Page, path: string, testId: string) {
  await page.goto(path);
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  const submit = () => form.locator('button[type="submit"]').click();
  return { form, field, submit };
}

test("ce: cost and usage page and its sections", async ({ page }) => {
  await page.goto("/ce");
  await expect(page.getByRole("heading", { name: "Cost and usage" })).toBeVisible();
  await page.getByRole("link", { name: "Anomaly detection" }).first().click();
  await expect(page.getByRole("heading", { name: "Cost anomaly detection" })).toBeVisible();
});

test("ce: a monitor repairs account IDs written the way AWS shows them", async ({ page }) => {
  const { form, field, submit } = await openSheet(page, "/ce/anomalies", "create-monitor");
  const name = unique("dash-accounts");
  await form.locator('input[name="name"]').fill(name);
  await form.locator('select[name="kind"]').selectOption("accounts");
  const accounts = form.locator('input[name="accounts"]');
  await accounts.fill("1111-2222-3333");
  await accounts.blur();
  await expect(field("accounts")).toHaveAttribute("data-invalid", "pattern");
  await field("accounts").getByRole("button", { name: /111122223333/ }).click();
  await expect(accounts).toHaveValue("111122223333");
  await expect(field("accounts")).not.toHaveAttribute("data-invalid");
  await submit();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.locator("li.row").filter({ hasText: name })).toContainText("111122223333");
});

test("ce: an alert subscription checks its address against the frequency", async ({ page }) => {
  const topicName = unique("dash-cost-alerts");
  const topic = (await new SNSClient(sdk).send(new CreateTopicCommand({ Name: topicName }))).TopicArn!;
  // Subscriptions need a monitor to watch.
  let sheet = await openSheet(page, "/ce/anomalies", "create-monitor");
  const monitor = unique("dash-tagged");
  await sheet.form.locator('input[name="name"]').fill(monitor);
  await sheet.form.locator('select[name="kind"]').selectOption("tag");
  await sheet.form.locator('input[name="tagKey"]').fill("team");
  await sheet.form.locator('input[name="tagValues"]').fill("payments");
  await sheet.submit();
  await expect(page.locator("dialog[open]")).toHaveCount(0);

  sheet = await openSheet(page, "/ce/anomalies", "create-subscription");
  const { form, field, submit } = sheet;
  const name = unique("dash-alerts");
  await form.locator('input[name="name"]').fill(name);
  await form.locator('select[name="monitor"]').selectOption({ label: monitor });

  // Summaries go to email: a mistyped domain gets a suggestion.
  const address = () => form.locator('input[name="address"]');
  await address().fill("finops@gmial.com");
  await address().blur();
  await expect(field("address")).toHaveAttribute("data-invalid", "format");
  await field("address").getByRole("button", { name: /gmail\.com/ }).click();
  await expect(address()).toHaveValue("finops@gmail.com");

  // Immediate alerts go to SNS: a bare topic name expands to its ARN.
  await form.locator('select[name="frequency"]').selectOption("IMMEDIATE");
  await address().fill(topicName);
  await address().blur();
  await expect(field("address")).toHaveAttribute("data-invalid", "format");
  await field("address").getByRole("button", { name: /Expand to an ARN/ }).click();
  await expect(address()).toHaveValue(topic);

  // A negative threshold is clamped to the minimum.
  const threshold = form.locator('input[name="threshold"]');
  await threshold.fill("-5");
  await threshold.blur();
  await expect(field("threshold")).toHaveAttribute("data-invalid", "range");
  await field("threshold").getByRole("button", { name: /minimum/ }).click();
  await threshold.fill("250");

  await submit();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  const row = page.locator("li.row").filter({ hasText: name });
  await expect(row).toContainText(topic);
  await expect(row).toContainText("Immediate");
});

test("ce: cost categories repair JSON and suggest a free name", async ({ page }) => {
  const taken = unique("dash-teams");
  const { form, field, submit } = await openSheet(page, "/ce/categories", "create-cost-category");
  // Created after the page loaded: AWS's "already exists" lands on the name.
  await new CostExplorerClient(sdk).send(
    new CreateCostCategoryDefinitionCommand({
      Name: taken,
      RuleVersion: "CostCategoryExpression.v1",
      Rules: [{ Value: "Payments", Rule: { Tags: { Key: "team", Values: ["payments"] } } }],
    }),
  );
  const rules = form.locator('textarea[name="rules"]');
  await rules.fill('[{ Value: "Payments", Rule: { Tags: { Key: "team", Values: ["payments"] } } },]');
  await rules.blur();
  await expect(field("rules")).toHaveAttribute("data-invalid", "format");
  await field("rules").getByRole("button", { name: /Fix the JSON/ }).click();
  await expect(field("rules")).not.toHaveAttribute("data-invalid");
  expect(JSON.parse(await rules.inputValue())).toHaveLength(1);

  await form.locator('input[name="name"]').fill(taken);
  await submit();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(form.locator('input[name="name"]')).toHaveValue(`${taken}-2`);
  await submit();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.locator("li.row").filter({ hasText: `${taken}-2` })).toBeVisible();
});
