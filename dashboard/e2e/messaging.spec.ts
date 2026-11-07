import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("SQS: create a queue, send, peek and receive", async ({ page }) => {
  const queue = unique("dash-queue");
  await page.goto("/messaging/sqs");
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

test("SNS: a topic fans out to a queue", async ({ page }) => {
  const topic = unique("dash-topic");
  const queue = unique("dash-sub");
  await page.goto("/messaging/sqs");
  await submit(page, "create-queue", { name: queue });
  await page.getByRole("link", { name: queue }).click();
  const queueArn = (await page.locator("dt:has-text('ARN') + dd").textContent())!.trim();

  await page.goto("/messaging/sns");
  await submit(page, "create-topic", { name: topic });
  await page.getByRole("link", { name: topic }).click();
  await submit(page, "subscribe", { protocol: "sqs", endpoint: queueArn });
  await expect(page.getByRole("row").filter({ hasText: queueArn })).toBeVisible();
  await submit(page, "publish", { subject: "Hi", message: "fan-out works" });

  await page.goto(`/messaging/sqs/${queue}`);
  const peek = await submit(page, "receive-messages", { mode: "peek" });
  await expect(peek).toContainText("fan-out works");
});

test("EventBridge: put an event on the default bus", async ({ page }) => {
  await page.goto("/messaging/events");
  await expect(page.getByRole("link", { name: "default" })).toBeVisible();
  const result = await submit(page, "put-event", { detail: '{"from": "playwright"}' });
  await expect(result).toContainText("Put event");
});

test("SES: verify an identity, send mail and read the outbox", async ({ page }) => {
  const from = `${unique("sender")}@example.com`;
  const subject = unique("Subject");
  await page.goto("/messaging/ses");
  await submit(page, "create-identity", { identity: from });
  const row = page.getByRole("row").filter({ hasText: from });
  await row.getByRole("button", { name: "Mark verified" }).click();
  await expect(row.getByText("success")).toBeVisible();

  // The account is in the SES sandbox, so it may only mail verified addresses.
  await submit(page, "send-email", { from, to: from, subject, body: "Sent from Playwright" });
  await page.reload();
  const mail = page.getByRole("row").filter({ hasText: subject });
  await expect(mail).toBeVisible();
  await mail.getByText(subject).click();
  await expect(mail).toContainText("Sent from Playwright");
});
