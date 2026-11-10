import { CreateQueueCommand, SQSClient } from "@aws-sdk/client-sqs";
import { expect, test, type Page } from "@playwright/test";

import { sdk, unique } from "./helpers";

// The shared inline validation (packages/ui: validation.ts, fields.tsx),
// exercised on SQS's create-queue sheet: problems show on the field with
// one-click repairs, and errors MWS returns land on the field they concern.

async function openSheet(page: Page) {
  await page.goto("/sqs");
  const form = page.locator("dialog[open]").getByTestId("create-queue").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("create-queue-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const name = form.locator('input[name="name"]');
  const field = form.locator(".field").filter({ has: page.locator('input[name="name"]') });
  return { form, name, field };
}

test("validation: problems show in the field with repairs", async ({ page }) => {
  const { form, name, field } = await openSheet(page);

  // Nothing is flagged while typing for the first time...
  const queue = unique("Dash Orders");
  await name.fill(queue);
  await expect(field.locator(".field-issue")).toHaveCount(0);
  // ...but leaving the field shows the problem and a fix.
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "pattern");
  const fix = field.getByRole("button", { name: /Replace spaces/ });
  await expect(fix).toContainText(queue.replace(/\s+/g, "-"));
  await fix.click();
  await expect(name).toHaveValue(queue.replace(/\s+/g, "-"));
  await expect(field).not.toHaveAttribute("data-invalid");

  // An empty required name blocks the submission in place and offers a
  // generated one.
  await name.fill("");
  await form.locator('button[type="submit"]').click();
  await expect(field).toHaveAttribute("data-invalid", "required");
  await expect(name).toBeFocused();
  await field.getByRole("button", { name: /Generate/ }).click();
  await expect(name).not.toHaveValue("");
  await expect(field).not.toHaveAttribute("data-invalid");
});

test("validation: taken names and server conflicts suggest the next free name", async ({ page }) => {
  const queue = unique("dash-taken");
  const sqs = new SQSClient(sdk);
  await sqs.send(new CreateQueueCommand({ QueueName: queue }));

  // Known when the page loaded: flagged before submitting.
  let { name, field } = await openSheet(page);
  await name.fill(queue);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(field.getByRole("button", { name: /Use / })).toContainText(`${queue}-2`);

  // Created after the page loaded: MWS answers QueueNameExists, which lands
  // on the name field (not under the form) with the same repair.
  const later = unique("dash-later");
  ({ name, field } = await openSheet(page));
  await sqs.send(new CreateQueueCommand({ QueueName: later, Attributes: { DelaySeconds: "5" } }));
  await name.fill(later);
  await page.locator("dialog[open]").locator('select[name="dlq"]').selectOption({ index: 1 });
  await page.locator("dialog[open]").locator('button[type="submit"]').click();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field.getByRole("button", { name: /Use / }).click();
  await expect(name).toHaveValue(`${later}-2`);
  await page.locator("dialog[open]").locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByRole("link", { name: `${later}-2` }).first()).toBeVisible();
});
