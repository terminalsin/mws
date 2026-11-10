import { CostExplorerClient, CreateAnomalyMonitorCommand, CreateCostCategoryDefinitionCommand } from "@aws-sdk/client-cost-explorer";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { CreateTopicCommand, SNSClient } from "@aws-sdk/client-sns";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

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
  // The sheet opens on what the monitor watches; picking it fills in a name.
  await form.getByTestId("preset-accounts").click();
  await form.locator('input[name="name"]').fill(name);
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
  await sheet.form.getByTestId("preset-tag").click();
  await sheet.form.locator('input[name="name"]').fill(monitor);
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
  // The topic is known by name (it exists), so its own ARN is offered first.
  await field("address").getByRole("button", { name: /Expand to an ARN|^Use / }).first().click();
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

/** Seed one cost record for today (MWS's clock) through MWS's ledger API. */
async function seedCost(request: import("@playwright/test").APIRequestContext, record: Record<string, unknown>) {
  const account = (await new STSClient(sdk).send(new GetCallerIdentityCommand({}))).Account!;
  const now = (await (await request.get(`${sdk.endpoint}/_mws/clock`)).json()).now as string;
  const start = `${now.slice(0, 13)}:00:00Z`;
  const r = await request.post(`${sdk.endpoint}/_aws/ce/records`, { data: { records: [{ account, start, region: "us-east-1", ...record }] } });
  expect(r.ok(), await r.text()).toBeTruthy();
  return now.slice(0, 10);
}

test("ce: query costs by day, filtered and grouped", async ({ page, request }) => {
  const usage = unique("DashUsage");
  const today = await seedCost(request, { service: "Amazon Simple Storage Service", usageType: usage, cost: 12.34 });
  const tomorrow = new Date(new Date(`${today}T00:00:00Z`).getTime() + 86_400_000).toISOString().slice(0, 10);
  await page.goto("/ce");
  const form = page.getByTestId("cost-query");
  await form.locator('[name="start"]').fill(today);
  await form.locator('[name="end"]').fill(tomorrow);
  await form.locator('[name="granularity"]').selectOption("DAILY");
  await form.locator('[name="group"]').first().selectOption("DIMENSION:SERVICE");
  // Filters wait under More.
  await form.locator(".more-fields > summary").click();
  await form.locator('[name="filter"]').selectOption("DIMENSION:USAGE_TYPE");
  await form.locator('[name="values"]').fill(usage);
  await form.getByRole("button", { name: "Apply" }).click();
  await expect(page).toHaveURL(/granularity=DAILY/);
  const table = page.getByRole("table", { name: "Cost breakdown" });
  await expect(table.getByRole("row").filter({ hasText: "Amazon Simple Storage Service" })).toContainText("$12.34");
  await expect(page.getByTestId("forecast-unavailable").or(page.getByText("Forecast this month"))).toBeVisible();
});

test("ce: activate a cost allocation tag found in the data", async ({ page, request }) => {
  const key = unique("dashcc");
  await seedCost(request, { service: "Amazon Simple Storage Service", cost: 1, tags: { [key]: "blue" } });
  await page.goto("/ce/tags");
  await expect(row(page, key)).toContainText("Inactive");
  await row(page, key).getByRole("button", { name: `Activate ${key}` }).click();
  await expect(row(page, key)).toContainText("Active");
  await expect(row(page, key).getByRole("link", { name: key })).toHaveAttribute("href", new RegExp(`group=TAG%3A${key}`));
});

test("ce: open a cost category and change its default value", async ({ page }) => {
  const name = unique("dash-cat");
  const out = await new CostExplorerClient(sdk).send(
    new CreateCostCategoryDefinitionCommand({ Name: name, RuleVersion: "CostCategoryExpression.v1", Rules: [{ Value: "Payments", Rule: { Tags: { Key: "team", Values: ["payments"] } } }] }),
  );
  await page.goto("/ce/categories");
  await row(page, name).getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(row(page, "Payments")).toBeVisible();
  await submit(page, "edit-cost-category", { default: "Shared" });
  await expect(row(page, "Shared")).toContainText("default");
  expect(out.CostCategoryArn).toBeTruthy();
});

test("ce: rename an anomaly monitor", async ({ page }) => {
  const name = unique("dash-mon");
  await new CostExplorerClient(sdk).send(
    new CreateAnomalyMonitorCommand({ AnomalyMonitor: { MonitorName: name, MonitorType: "CUSTOM", MonitorSpecification: { Tags: { Key: "team", Values: ["x"] } } } }),
  );
  await page.goto("/ce/anomalies");
  const opener = row(page, name).getByRole("button", { name: `Rename ${name}` });
  await opener.click();
  const form = page.locator("dialog[open]").getByTestId("rename-monitor").and(page.locator("form"));
  await form.locator('[name="name"]').fill(`${name}-renamed`);
  await form.locator('button[type="submit"]').click();
  await expect(row(page, `${name}-renamed`).first()).toBeVisible();
});
