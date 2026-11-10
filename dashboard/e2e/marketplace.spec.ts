import { expect, test, type Page } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("Marketplace: subscribe a buyer and meter usage", async ({ page }) => {
  const title = unique("Dash SaaS");
  await page.goto("/marketplace");
  await submit(page, "create-product", { title, dimensions: "users requests" });
  await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
  const subscribed = await submit(page, "subscribe", { account: "111122223333", "dim:users": "10" });
  await expect(subscribed).toContainText("x-amzn-marketplace-token");
  await page.reload();
  await expect(row(page, "111122223333")).toContainText("users 10");
  await submit(page, "meter", { dimension: "users", quantity: "7" });
  await page.reload();
  await expect(page.getByLabel("Usage by dimension")).toContainText("7");
  await page.goto("/marketplace?tab=records");
  await expect(page.locator("li.row").filter({ hasText: title }).first()).toContainText("7 × users");
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, input: (name: string) => form.locator(`[name="${name}"]`) };
}

test("Marketplace: fields repair dimensions, accounts and quantities in place", async ({ page }) => {
  await page.goto("/marketplace");
  const product = await openSheet(page, "create-product");
  const title = unique("Dash Fixes");
  await product.input("title").fill(title);

  // A repeated dimension is flagged and removed with one click.
  const dims = product.input("dimensions");
  await dims.fill("users requests users");
  await dims.blur();
  await expect(product.field("dimensions")).toHaveAttribute("data-invalid", "format");
  await product.field("dimensions").getByRole("button", { name: /Remove the second users/ }).click();
  await expect(dims).toHaveValue("users, requests");
  // A name Marketplace would not accept is reshaped, keeping the others.
  await dims.fill("users, api$calls");
  await dims.blur();
  await expect(product.field("dimensions")).toContainText("api$calls");
  await product.field("dimensions").getByRole("button", { name: /in api\$calls/ }).click();
  await expect(dims).toHaveValue("users, api-calls");
  await expect(product.field("dimensions")).not.toHaveAttribute("data-invalid");
  await product.form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();

  // A formatted account id loses its dashes; an empty one can be generated.
  const sub = await openSheet(page, "subscribe");
  const account = sub.input("account");
  await account.fill("1111-2222-3333");
  await account.blur();
  await expect(sub.field("account")).toHaveAttribute("data-invalid", "pattern");
  await sub.field("account").getByRole("button", { name: /Remove unsupported characters/ }).click();
  await expect(account).toHaveValue("111122223333");
  await account.fill("");
  await sub.form.locator('button[type="submit"]').click();
  await expect(sub.field("account")).toHaveAttribute("data-invalid", "required");
  await sub.field("account").getByRole("button", { name: /Generate/ }).click();
  await expect(account).toHaveValue(/^\d{12}$/);
  await sub.form.locator('button[type="submit"]').click();
  await expect(sub.form.getByRole("status")).toHaveClass(/ok/);

  // Quantities follow BatchMeterUsage's range.
  await page.reload();
  const meter = await openSheet(page, "meter");
  const quantity = meter.input("quantity");
  await quantity.fill("-3");
  await quantity.blur();
  await expect(meter.field("quantity")).toHaveAttribute("data-invalid", "range");
  await meter.field("quantity").getByRole("button", { name: /minimum/ }).click();
  await expect(quantity).toHaveValue("0");
  await quantity.fill("2.5");
  await quantity.blur();
  await expect(meter.field("quantity")).toHaveAttribute("data-invalid", "type");
  await meter.field("quantity").getByRole("button", { name: /Use 3/ }).click();
  await expect(quantity).toHaveValue("3");
});
