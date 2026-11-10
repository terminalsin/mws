import { EventBridgeClient, PutRuleCommand } from "@aws-sdk/client-eventbridge";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("EventBridge: put an event on the default bus", async ({ page }) => {
  await page.goto("/events");
  await submit(page, "put-event", { detail: '{"from": "playwright"}' });
});

/** Open the sheet holding the form `testId`; returns the form and a
 * locator for the field around a named control. */
async function openSheet(page: Page, testId: string) {
  await page.goto("/events");
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const control = (name: string) => form.locator(`[name="${name}"]`);
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, control, field };
}

test("EventBridge: rule fields repair names, patterns and schedules", async ({ page }) => {
  const { form, control, field } = await openSheet(page, "create-rule");
  const name = unique("Dash Rule");

  await control("name").fill(name);
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /Replace spaces/ }).click();
  await expect(control("name")).toHaveValue(name.replace(/\s+/g, "-"));

  // A bare value where EventBridge wants a list of values.
  await control("pattern").fill('{"source": "dash.orders"}');
  await control("pattern").blur();
  await expect(field("pattern")).toHaveAttribute("data-invalid", "format");
  await expect(field("pattern")).toContainText('"source" must be an object or an array');
  await field("pattern").getByRole("button", { name: "Fix the pattern" }).click();
  expect(JSON.parse(await control("pattern").inputValue())).toEqual({ source: ["dash.orders"] });
  await expect(field("pattern")).not.toHaveAttribute("data-invalid");

  // Plain words and Unix cron become EventBridge schedules.
  await control("schedule").fill("5 minutes");
  await control("schedule").blur();
  await field("schedule").getByRole("button", { name: /rate\(5 minutes\)/ }).click();
  await expect(control("schedule")).toHaveValue("rate(5 minutes)");
  await control("schedule").fill("*/10 * * * *");
  await control("schedule").blur();
  await field("schedule").getByRole("button", { name: /cron\(0\/10 \* \* \* \? \*\)/ }).click();
  await expect(control("schedule")).toHaveValue("cron(0/10 * * * ? *)");
  await control("schedule").fill("");

  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, name.replace(/\s+/g, "-"))).toBeVisible();
});

test("EventBridge: taken rule names and server rejections land on their field", async ({ page }) => {
  const taken = unique("dash-taken");
  await new EventBridgeClient(sdk).send(new PutRuleCommand({ Name: taken, EventPattern: '{"source": ["dash.taken"]}' }));

  const { form, control, field } = await openSheet(page, "create-rule");
  await control("name").fill(taken);
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(control("name")).toHaveValue(`${taken}-2`);

  // Valid JSON in the right shape, but an unknown matcher: MWS answers
  // InvalidEventPatternException, which shows on the pattern field.
  await control("pattern").fill('{"source": [{"prefixx": "dash"}]}');
  await form.locator('button[type="submit"]').click();
  await expect(field("pattern")).toHaveAttribute("data-invalid", "server");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
});

test("EventBridge: event fields drop reserved sources and fix the detail", async ({ page }) => {
  const { form, control, field } = await openSheet(page, "put-event");

  await control("source").fill("aws.orders");
  await control("source").blur();
  await expect(field("source")).toContainText("aws. is reserved");
  await field("source").getByRole("button", { name: /Drop aws\./ }).click();
  await expect(control("source")).toHaveValue("orders");

  await control("detail").fill("{id: 'o-1',}");
  await control("detail").blur();
  await expect(field("detail")).toHaveAttribute("data-invalid", "format");
  await field("detail").getByRole("button", { name: "Fix the JSON" }).click();
  expect(JSON.parse(await control("detail").inputValue())).toEqual({ id: "o-1" });

  // JSON, but not an object: the action rejects it on the field.
  await control("detail").fill("[1, 2]");
  await form.locator('button[type="submit"]').click();
  await expect(field("detail")).toContainText("Must be a JSON object");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
});
