import { expect, test, type Page } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("EFS: a file system with an access point", async ({ page }) => {
  const name = unique("dash-fs");
  await page.goto("/efs");
  await submit(page, "create-file-system", { name, vpc: "" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await submit(page, "create-access-point", { name: "app", path: "/app" });
  await expect(row(page, "/app")).toBeVisible();
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => ({
    input: form.locator(`[name="${name}"]`),
    box: form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) }),
  });
  return { form, field };
}

test("EFS: fields repair names, root directories and user ids in place", async ({ page }) => {
  await page.goto("/efs");
  let { form, field } = await openSheet(page, "create-file-system");

  // The Name tag rejects "!": offered without it.
  const name = field("name");
  const fs = unique("dash-fs-check");
  await name.input.fill(`${fs}!`);
  await name.input.blur();
  await expect(name.box).toHaveAttribute("data-invalid", "pattern");
  await name.box.getByRole("button", { name: /Remove unsupported/ }).click();
  await expect(name.input).toHaveValue(fs);
  await expect(name.box).not.toHaveAttribute("data-invalid");
  await form.locator('select[name="vpc"]').selectOption("");
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: fs })).toBeVisible();

  ({ form, field } = await openSheet(page, "create-access-point"));
  const path = field("path");
  // A relative path with a doubled slash, a space and a trailing slash
  // becomes one absolute, clean path.
  await path.input.fill("srv//my data/");
  await path.input.blur();
  await expect(path.box).toHaveAttribute("data-invalid", "format");
  await path.box.getByRole("button", { name: /Clean up the path/ }).click();
  await expect(path.input).toHaveValue("/srv/my-data");
  await expect(path.box).not.toHaveAttribute("data-invalid");

  // EFS allows four levels: the fix keeps the first four.
  await path.input.fill("/a/b/c/d/e");
  await path.input.blur();
  await expect(path.box).toHaveAttribute("data-invalid", "pattern");
  await path.box.getByRole("button", { name: /Keep 4 levels/ }).click();
  await expect(path.input).toHaveValue("/a/b/c/d");

  // A user id past the 32-bit range is clamped to the largest one.
  const uid = field("uid");
  await uid.input.fill("5000000000");
  await uid.input.blur();
  await expect(uid.box).toHaveAttribute("data-invalid", "range");
  await uid.box.getByRole("button", { name: /Lower to the maximum/ }).click();
  await expect(uid.input).toHaveValue("4294967295");

  await form.locator('button[type="submit"]').click();
  await expect(row(page, "/a/b/c/d")).toBeVisible();
});
