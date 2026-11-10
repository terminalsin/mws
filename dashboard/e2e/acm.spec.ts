import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("Certificates: a private CA issues a certificate requested through ACM", async ({ page }) => {
  const cn = unique("Dash Root CA");
  await page.goto("/pca");
  await submit(page, "create-ca", { cn });
  await expect(page.getByRole("heading", { level: 1, name: cn })).toBeVisible();
  await submit(page, "install-ca-cert");
  await expect(page.locator(".specs")).toContainText("active");

  const domain = `${unique("svc")}.internal.example`;
  await page.goto("/acm");
  await submit(page, "request-certificate", { domains: domain, pca: `Private · ${cn}` });
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  await expect(page.locator(".specs")).toContainText(/Issued|Pending/);
});
