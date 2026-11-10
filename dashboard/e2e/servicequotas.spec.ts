import { GetServiceQuotaCommand, RequestServiceQuotaIncreaseCommand, ServiceQuotasClient } from "@aws-sdk/client-service-quotas";
import { expect, test, type Page } from "@playwright/test";

import { sdk } from "./helpers";

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
