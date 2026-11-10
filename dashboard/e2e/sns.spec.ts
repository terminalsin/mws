import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("SNS: a topic fans out to a queue", async ({ page }) => {
  const topic = unique("dash-topic");
  const queue = unique("dash-sub");
  await page.goto("/sqs");
  await submit(page, "create-queue", { name: queue });
  await page.getByRole("link", { name: queue }).click();
  const queueArn = (await page.locator("dt:has-text('ARN') + dd").first().textContent())!.trim();

  await page.goto("/sns");
  await submit(page, "create-topic", { name: topic });
  await page.getByRole("link", { name: topic }).click();
  await submit(page, "subscribe", { protocol: "sqs", endpoint: queueArn });
  await expect(row(page, queue)).toBeVisible();
  await submit(page, "publish", { subject: "Hi", message: "fan-out works" });

  await page.goto(`/sqs/${queue}`);
  const peek = await submit(page, "receive-messages", { mode: "peek" });
  await expect(peek).toContainText("fan-out works");
});
