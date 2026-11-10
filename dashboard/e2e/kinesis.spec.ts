import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("Kinesis: put a record and read it back in the data viewer", async ({ page }) => {
  const name = unique("dash-stream");
  await page.goto("/kinesis");
  await submit(page, "create-stream", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  // A new stream is CREATING for a moment, as in AWS.
  await expect(async () => {
    await page.reload();
    await expect(page.locator(".specs")).toContainText("active", { timeout: 1000 });
  }).toPass();
  await submit(page, "put-record", { key: "user-1", data: '{"clicked":"buy"}' });
  await page.reload();
  await expect(page.getByLabel("Records")).toContainText('{"clicked":"buy"}');
});
