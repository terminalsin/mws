import { CloudTrailClient, DeleteTrailCommand } from "@aws-sdk/client-cloudtrail";
import { expect, test, type Page } from "@playwright/test";

import { sdk, unique } from "./helpers";

// AWS allows five trails per region, and the suites share one MWS: every
// trail a test makes is deleted again.
const made: string[] = [];
test.afterAll(async () => {
  const client = new CloudTrailClient(sdk);
  for (const name of made) await client.send(new DeleteTrailCommand({ Name: name })).catch(() => {});
});

async function openSheet(page: Page) {
  const form = page.locator("dialog[open]").getByTestId("create-trail").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("create-trail-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const name = form.locator('input[name="name"]');
  const field = form.locator(".field").filter({ has: page.locator('input[name="name"]') });
  return { form, name, field };
}

test("CloudTrail: trail names are checked and repaired in place", async ({ page }) => {
  await page.goto("/cloudtrail?tab=trails");
  const { form, name, field } = await openSheet(page);

  // Separators side by side are tidied.
  const id = Date.now().toString(36);
  await name.fill(`audit ${id}--trail`);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "pattern");
  const fix = field.getByRole("button", { name: /Tidy separators/ });
  await expect(fix).toContainText(`audit-${id}-trail`);
  await fix.click();
  await expect(name).toHaveValue(`audit-${id}-trail`);
  await expect(field).not.toHaveAttribute("data-invalid");

  // Names shaped like an IP address are rejected, with a generated one.
  await name.fill("10.0.0.1");
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "pattern");
  await field.getByRole("button", { name: /Generate/ }).click();
  await expect(name).not.toHaveValue("10.0.0.1");
  await expect(field).not.toHaveAttribute("data-invalid");

  // Too short.
  await name.fill("ab");
  await form.locator('button[type="submit"]').click();
  await expect(field).toHaveAttribute("data-invalid", "tooShort");
  await expect(name).toBeFocused();
});

test("CloudTrail: an existing trail name suggests the next free one", async ({ page, browser }) => {
  const trail = unique("dash-trail");
  await page.goto("/cloudtrail?tab=trails");
  let { name, field } = await openSheet(page);

  // Another tab creates the trail after this one loaded...
  const other = await browser.newPage();
  await other.goto("/cloudtrail?tab=trails");
  const second = await openSheet(other);
  await second.name.fill(trail);
  await second.form.locator('button[type="submit"]').click();
  made.push(trail);
  await expect(other.locator("dialog[open]")).toHaveCount(0);
  await other.close();

  // ...so MWS answers TrailAlreadyExistsException, which lands on the name.
  await name.fill(trail);
  await page.locator("dialog[open]").locator('button[type="submit"]').click();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await expect(field.getByRole("button", { name: /Use / })).toContainText(`${trail}-2`);

  // Once the page knows the trail, the name is flagged before submitting.
  await page.reload();
  ({ name, field } = await openSheet(page));
  await name.fill(trail);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await field.getByRole("button", { name: /Use / }).click();
  await expect(name).toHaveValue(`${trail}-2`);
  made.push(`${trail}-2`);
  await page.locator("dialog[open]").locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByText(`${trail}-2`, { exact: true }).first()).toBeVisible();
});
