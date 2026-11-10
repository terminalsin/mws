import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

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
