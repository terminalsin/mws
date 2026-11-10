import { CreateQueueCommand, GetQueueAttributesCommand, SQSClient } from "@aws-sdk/client-sqs";
import { expect, test, type Page } from "@playwright/test";

import { sdk, submit, unique } from "./helpers";

test("SQS: create a queue, send, peek and receive", async ({ page }) => {
  const queue = unique("dash-queue");
  await page.goto("/sqs");
  await submit(page, "create-queue", { name: queue });
  await page.getByRole("link", { name: queue }).click();

  await submit(page, "send-message", { body: "hello from the console" });
  await page.reload();
  await expect(page.getByTestId("available")).toHaveText("1");

  const peek = await submit(page, "receive-messages", { mode: "peek" });
  await expect(peek).toContainText("hello from the console");
  const take = await submit(page, "receive-messages", { mode: "delete" });
  await expect(take).toContainText("Received and deleted 1");
  await page.reload();
  await expect(page.getByTestId("available")).toHaveText("0");
});

/** Open the sheet holding the form `testId` and return the form. */
async function sheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, control: (name: string) => form.locator(`[name="${name}"]`) };
}

test("SQS: configuration converts durations and repairs the policy in place", async ({ page }) => {
  const queue = unique("dash-config");
  const sqs = new SQSClient(sdk);
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: queue }));
  await page.goto(`/sqs/${queue}`);
  const { form, field, control } = await sheet(page, "queue-config");

  // "5m" in a seconds field converts to seconds.
  await control("VisibilityTimeout").fill("5m");
  await control("VisibilityTimeout").blur();
  await expect(field("VisibilityTimeout")).toHaveAttribute("data-invalid", "type");
  await field("VisibilityTimeout").getByRole("button", { name: /5m in seconds/ }).click();
  await expect(control("VisibilityTimeout")).toHaveValue("300");
  await expect(field("VisibilityTimeout")).not.toHaveAttribute("data-invalid");

  // Out of range: the range reads as a duration, and the fix clamps.
  await control("MessageRetentionPeriod").fill("30");
  await control("MessageRetentionPeriod").blur();
  await expect(field("MessageRetentionPeriod")).toContainText("1m–2w");
  await field("MessageRetentionPeriod").getByRole("button", { name: /minimum/ }).click();
  await expect(control("MessageRetentionPeriod")).toHaveValue("60");

  // Hand-written JSON gets a one-click fix.
  await control("Policy").fill(
    `{Version: '2012-10-17', Statement: [{Effect: 'Allow', Principal: '*', Action: 'sqs:SendMessage', Resource: '*'}],}`,
  );
  await control("Policy").blur();
  await expect(field("Policy")).toHaveAttribute("data-invalid", "format");
  await field("Policy").getByRole("button", { name: /Fix the (JSON|policy)/ }).click();
  await expect(field("Policy")).not.toHaveAttribute("data-invalid");

  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  const { Attributes } = await sqs.send(new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ["All"] }));
  expect(Attributes?.VisibilityTimeout).toBe("300");
  expect(Attributes?.MessageRetentionPeriod).toBe("60");
  expect(JSON.parse(Attributes?.Policy ?? "{}").Statement[0].Action).toBe("sqs:SendMessage");
});

test("SQS: FIFO sends repair the group ID and generate a deduplication ID", async ({ page }) => {
  const queue = `${unique("dash-fifo")}.fifo`;
  const sqs = new SQSClient(sdk);
  await sqs.send(new CreateQueueCommand({ QueueName: queue, Attributes: { FifoQueue: "true" } }));
  await page.goto(`/sqs/${encodeURIComponent(queue)}`);
  const { form, field, control } = await sheet(page, "send-message");

  await control("body").fill("ordered");
  await control("group").fill("orders eu");
  await control("group").blur();
  await expect(field("group")).toHaveAttribute("data-invalid", "pattern");
  await field("group").getByRole("button", { name: /orders-eu/ }).click();
  await expect(control("group")).toHaveValue("orders-eu");

  // The missing deduplication ID blocks the send in place, with a fresh one on offer.
  await form.locator('button[type="submit"]').click();
  await expect(field("dedup")).toHaveAttribute("data-invalid", "required");
  await field("dedup").getByRole("button", { name: /Generate/ }).click();
  await expect(control("dedup")).not.toHaveValue("");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await page.reload();
  await expect(page.getByTestId("available")).toHaveText("1");
});

test("SQS: a .fifo name makes a FIFO queue without ticking FIFO", async ({ page }) => {
  const queue = `${unique("dash-auto")}.fifo`;
  await page.goto("/sqs");
  await submit(page, "create-queue", { name: queue });
  await expect(page.locator("li.row").filter({ hasText: queue }).getByText("FIFO", { exact: true })).toBeVisible();
});
