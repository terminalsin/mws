import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("SES: verify an identity, send mail and read the outbox", async ({ page }) => {
  const from = `${unique("sender")}@example.com`;
  const subject = unique("Subject");
  await page.goto("/ses");
  await submit(page, "create-identity", { identity: from });
  await row(page, from).getByRole("button", { name: `Verify ${from}` }).click();
  await expect(row(page, from).getByRole("button", { name: `Verify ${from}` })).toHaveCount(0);

  // The account is in the SES sandbox, so it may only mail verified addresses.
  await submit(page, "send-email", { from, to: from, subject, body: "Sent from Playwright" });
  await page.goto("/ses?tab=outbox");
  await expect(page.getByText(subject)).toBeVisible();
});
