import { CloudTrailClient, DeleteTrailCommand, GetTrailCommand } from "@aws-sdk/client-cloudtrail";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

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

test("CloudTrail: trail detail, edit, event selectors and delete", async ({ page }) => {
  const trail = unique("dash-detail");
  await page.goto("/cloudtrail?tab=trails");
  await submit(page, "create-trail", { name: trail });
  made.push(trail);
  await row(page, trail).getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1, name: trail })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("Logging");
  await expect(page.locator(".specs")).toContainText("Validated");

  // Edit: a single-Region trail without global events or validation. (A key prefix would
  // need the bucket policy to allow the prefixed path, as on AWS.)
  await submit(page, "edit-trail", { multi: "off", global: "off", validation: "off" });
  await expect(page.locator("main")).toContainText("Excluded");
  await expect(page.locator(".specs")).not.toContainText("Validated");

  // Basic selectors: write-only management events plus all S3 data events.
  await submit(page, "edit-selectors", { rw: "WriteOnly", s3: "*" });
  const selectors = page.locator("section").filter({ has: page.getByRole("heading", { name: "Event selectors" }) });
  await expect(selectors).toContainText("Write");
  await expect(selectors).toContainText("Data: AWS::S3::Object");

  // Logging can be stopped and started again.
  const toggle = page.getByTestId("toggle-logging").and(page.locator("form"));
  await toggle.locator('button[type="submit"]').click();
  await expect(page.locator(".specs")).toContainText("Off");

  await submit(page, "edit-trail-tags", { tags: "team=dash" });
  await expect(page.locator("main")).toContainText("team");

  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-trail").and(page.locator("form")).locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/\/cloudtrail\?tab=trails|\/cloudtrail$/);
  await expect(page.getByText(trail, { exact: true })).toHaveCount(0);
});

test("CloudTrail: event history lookup, time range and event detail", async ({ page }) => {
  const trail = unique("dash-event");
  const client = new CloudTrailClient(sdk);
  await page.goto("/cloudtrail?tab=trails");
  await submit(page, "create-trail", { name: trail });
  made.push(trail);

  // Look the CreateTrail call up by resource name: a write event.
  await page.goto(`/cloudtrail?key=ResourceName&value=${encodeURIComponent(trail)}`);
  const event = row(page, "CreateTrail");
  await expect(event).toBeVisible();
  await expect(event).toContainText("Write");

  // A range that ends before the trail existed finds nothing.
  await page.goto(`/cloudtrail?key=ResourceName&value=${encodeURIComponent(trail)}&end=2020-01-01T00:00`);
  await expect(row(page, "CreateTrail")).toHaveCount(0);

  // The detail page shows the record and its request parameters.
  await page.goto(`/cloudtrail?key=ResourceName&value=${encodeURIComponent(trail)}`);
  await row(page, "CreateTrail").getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1, name: "CreateTrail" })).toBeVisible();
  await expect(page.locator("main")).toContainText("cloudtrail.amazonaws.com");
  await expect(page.locator("pre[aria-label='Request parameters']")).toContainText(trail);

  // Read-only calls carry no Write pill.
  await client.send(new GetTrailCommand({ Name: trail }));
  await page.goto(`/cloudtrail?key=EventName&value=GetTrail`);
  const read = row(page, "GetTrail").first();
  await expect(read).toBeVisible();
  await expect(read).not.toContainText("Write");
});
