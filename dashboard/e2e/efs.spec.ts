import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("EFS: a file system with an access point", async ({ page }) => {
  const name = unique("dash-fs");
  await page.goto("/efs");
  await submit(page, "create-file-system", { name, vpc: "" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await submit(page, "create-access-point", { name: "app", path: "/app" });
  await expect(row(page, "/app")).toBeVisible();
});
