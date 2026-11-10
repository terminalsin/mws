import { expect, test, type Page } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("RDS: create a PostgreSQL database and find its connection command", async ({ page }) => {
  const id = unique("dash-db");
  await page.goto("/rds");
  await submit(page, "create-database", { engine: "postgres", id, username: "app", password: "correct-horse-battery" });
  await expect(page.getByRole("heading", { level: 1, name: id })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("postgres");

  // A snapshot name already used on this database is flagged in place,
  // with the next free name one click away.
  const snap = `${id}-before-upgrade`;
  await submit(page, "take-snapshot", { name: snap });
  const sheet = await openSheet(page, "take-snapshot");
  const field = sheet.field("name");
  await field.locator("input").fill(snap);
  await field.locator("input").blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await field.getByRole("button", { name: /Use / }).click();
  await expect(field.locator("input")).toHaveValue(`${snap}-2`);
  await expect(field).not.toHaveAttribute("data-invalid");
  await sheet.form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);

  await page.goto("/rds");
  await expect(row(page, id)).toBeVisible();
});

test("RDS: create-database fields repair what RDS would reject", async ({ page }) => {
  await page.goto("/rds");
  const { form, field } = await openSheet(page, "create-database");

  // RDS identifiers: lower case, single hyphens.
  const id = field("id");
  await id.locator("input").fill("Orders DB");
  await id.locator("input").blur();
  await expect(id).toHaveAttribute("data-invalid", "pattern");
  await id.getByRole("button", { name: /Lowercase/ }).click();
  await expect(id.locator("input")).toHaveValue("orders-db");
  await expect(id).not.toHaveAttribute("data-invalid");

  // Passwords: printable ASCII without / @ " or spaces, or a generated one.
  const password = field("password");
  await password.locator("input").fill("p@ss word");
  await password.locator("input").blur();
  await expect(password).toHaveAttribute("data-invalid", "pattern");
  await expect(password.getByRole("button", { name: /Remove unsupported/ })).toBeVisible();
  await password.locator("input").fill("");
  await form.locator('button[type="submit"]').click();
  await expect(password).toHaveAttribute("data-invalid", "required");
  await password.getByRole("button", { name: /Generate/ }).click();
  await expect(password.locator("input")).not.toHaveValue("");
  await expect(password).not.toHaveAttribute("data-invalid");

  // Aurora has no micro instances: the untouched default follows the
  // engine, and a typed one is answered with the sizes Aurora offers.
  const cls = field("class");
  await form.locator('select[name="engine"]').selectOption("aurora-postgresql");
  await expect(cls.locator("input")).toHaveValue("db.t4g.medium");
  await expect(form.locator('input[name="storage"]')).toHaveCount(0);
  await cls.locator("input").fill("db.t4g.micro");
  await cls.locator("input").blur();
  await expect(cls).toHaveAttribute("data-invalid", "enum");
  await cls.getByRole("button", { name: /db\.t4g\.medium/ }).click();
  await expect(cls).not.toHaveAttribute("data-invalid");

  // MySQL user names stop at 32 characters.
  await form.locator('select[name="engine"]').selectOption("mysql");
  const user = field("username");
  await expect(user.locator("input")).toHaveValue("admin");
  await user.locator("input").fill("a".repeat(40));
  await user.locator("input").blur();
  await expect(user).toHaveAttribute("data-invalid", "tooLong");
  await user.getByRole("button", { name: /Shorten to 32/ }).click();
  await expect(user).not.toHaveAttribute("data-invalid");
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field };
}
