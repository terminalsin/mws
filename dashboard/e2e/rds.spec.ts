import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("RDS: create a PostgreSQL database and find its connection command", async ({ page }) => {
  const id = unique("dash-db");
  await page.goto("/rds");
  await submit(page, "create-database", { engine: "postgres", id, username: "app", password: "correct-horse-battery" });
  await expect(page.getByRole("heading", { level: 1, name: id })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("postgres");
  await page.goto("/rds");
  await expect(row(page, id)).toBeVisible();
});
