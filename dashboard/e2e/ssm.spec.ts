import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("Parameter Store: browse by path; SecureStrings stay hidden until asked", async ({ page }) => {
  const root = unique("dash");
  const name = `/${root}/db/password`;
  await page.goto("/ssm");
  await submit(page, "put-parameter", { name, type: "SecureString", value: "s3cret" });
  await page.goto(`/ssm?path=${encodeURIComponent(`/${root}/db/`)}`);
  await expect(row(page, "password")).not.toContainText("s3cret");
  await page.getByRole("link", { name: "Reveal values" }).click();
  await expect(row(page, "password")).toContainText("s3cret");
});
