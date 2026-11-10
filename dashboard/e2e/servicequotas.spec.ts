import { GetServiceQuotaCommand, RequestServiceQuotaIncreaseCommand, ServiceQuotasClient } from "@aws-sdk/client-service-quotas";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit } from "./helpers";

// The request-increase sheet validates the new value in place: it must be
// above the quota's current value, and a value MWS rejects because the quota
// rose meanwhile gets the new floor as its repair.

const quotas = new ServiceQuotasClient(sdk);

async function current(ServiceCode: string, QuotaCode: string) {
  return (await quotas.send(new GetServiceQuotaCommand({ ServiceCode, QuotaCode }))).Quota?.Value ?? 0;
}

async function openIncrease(page: Page, service: string, code: string) {
  await page.goto(`/servicequotas?service=${service}`);
  const form = page.locator("dialog[open]").getByTestId(`increase-${code}`).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`increase-${code}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const value = form.locator('input[name="value"]');
  const field = form.locator(".field").filter({ has: page.locator('input[name="value"]') });
  return { form, value, field };
}

test("service quotas: a value at or below the current quota is raised in place", async ({ page }) => {
  const now = await current("ebs", "L-9CF3C2EB");
  const { value, field } = await openIncrease(page, "ebs", "L-9CF3C2EB");
  await expect(field.locator(".field-hint")).toHaveText(`Now ${now}`);

  await value.fill(String(now));
  await value.blur();
  await expect(field).toHaveAttribute("data-invalid", "range");
  await field.getByRole("button", { name: /Raise to the minimum/ }).click();
  await expect(value).toHaveValue(String(Math.floor(now) + 1));
  await expect(field).not.toHaveAttribute("data-invalid");
});

test("service quotas: a quota raised since the page loaded moves the field's floor", async ({ page }) => {
  const [service, code] = ["ebs", "L-17AF77E8"];
  const before = await current(service, code);
  const { form, value, field } = await openIncrease(page, service, code);

  // Someone else raises the quota; the request settles on MWS's clock.
  const raised = before + 10;
  await quotas.send(new RequestServiceQuotaIncreaseCommand({ ServiceCode: service, QuotaCode: code, DesiredValue: raised }));
  await expect.poll(() => current(service, code), { timeout: 20_000 }).toBe(raised);

  // Still valid for the stale page, so MWS answers; its floor lands on the field.
  await value.fill(String(before + 5));
  await form.locator('button[type="submit"]').click();
  await expect(field).toHaveAttribute("data-invalid", "range");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field.getByRole("button", { name: /Raise to the minimum/ }).click();
  await expect(value).toHaveValue(String(raised + 1));
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
});

test("service quotas: a request shows as pending, and the quota updates itself once approved", async ({ page }) => {
  // VPCs per Region: adjustable, and no other spec raises it.
  const [service, code] = ["vpc", "L-F678F1CE"];
  const before = await current(service, code);
  await page.goto(`/servicequotas?service=${service}`);
  await submit(page, `increase-${code}`, { value: String(before + 1) });
  // Approved a second later on MWS's clock: the row moves on without a reload.
  await expect(row(page, code).locator(".pill").filter({ hasText: new RegExp(`^${before + 1}$`) })).toBeVisible({ timeout: 30_000 });

  // The quota's page has the request in its history, approved.
  await row(page, code).getByRole("link").click();
  await expect(page).toHaveURL(new RegExp(`/servicequotas/quota\\?service=${service}&code=${code}`));
  await expect(page.getByRole("list", { name: "Requests" })).toContainText("approved");

  // The account-wide history links each request to its quota.
  await page.goto("/servicequotas?tab=requests");
  await expect(page.getByRole("list", { name: "Requests" }).locator(`a[href*="code=${code}"]`).first()).toBeVisible();
});

test("service quotas: a utilization report is generated", async ({ page }) => {
  await page.goto("/servicequotas?tab=utilization");
  await page.getByTestId("generate-report").locator("button").click();
  await expect(page).toHaveURL(/report=/);
  await expect(page.locator(".facts")).toContainText("completed", { timeout: 30_000 });
});

test("service quotas: automatic management starts and stops", async ({ page }) => {
  await page.goto("/servicequotas/automatic");
  await submit(page, "auto-management", { exclude: "ec2=L-1216C47A" });
  await expect(page.locator(".facts")).toContainText("enabled");
  await expect(row(page, "L-1216C47A")).toBeVisible();
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("stop-auto-management").locator("button").click();
  await expect(page.locator(".facts")).toContainText("disabled");
});
