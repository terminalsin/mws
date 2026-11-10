import { expect, test } from "@playwright/test";

import { row, rowAction, submit, unique } from "./helpers";

test("Route 53: create a zone, add and delete a record", async ({ page }) => {
  const domain = `${unique("dash")}.example.com`;
  await page.goto("/route53");
  await submit(page, "create-zone", { name: domain });
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  await submit(page, "create-record", { name: `www.${domain}`, type: "A", values: "192.0.2.10", ttl: "60" });
  await expect(row(page, "192.0.2.10")).toBeVisible();
  await rowAction(page, "192.0.2.10", /^Delete www/);
  await expect(row(page, "192.0.2.10")).toHaveCount(0);
});
