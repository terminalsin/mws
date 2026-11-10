import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("create a bucket, write, read, download and delete objects", async ({ page, request }) => {
  const bucket = unique("dash-bucket");
  await page.goto("/s3");
  await submit(page, "create-bucket", { name: bucket });
  await page.getByRole("link", { name: bucket }).click();
  await expect(page.getByRole("heading", { level: 1, name: bucket })).toBeVisible();

  await submit(page, "put-text-object", { key: "docs/hello.json", body: '{"hello":"world"}', contentType: "application/json" });
  await page.locator("a.row-main", { hasText: "docs" }).click();
  await page.locator("a.row-main", { hasText: "hello.json" }).click();
  await expect(page.getByLabel("Object preview")).toContainText('"hello": "world"');

  const download = await request.get(`/api/s3/object?bucket=${bucket}&key=docs/hello.json`);
  expect(await download.json()).toEqual({ hello: "world" });

  await page.goto(`/s3/${bucket}`);
  await page.getByTestId("upload-object-open").click();
  const upload = page.getByTestId("upload-object").and(page.locator("form"));
  await upload.locator('input[type="file"]').setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("uploaded") });
  await upload.locator('button[type="submit"]').click();
  await expect(page.locator("a.row-main", { hasText: "notes.txt" })).toBeVisible();

  await page.getByRole("link", { name: "Properties" }).click();
  await expect(page.getByRole("button", { name: "Enable versioning" })).toBeVisible();
  await submit(page, "delete-bucket", { empty: "on" });
  await expect(page).toHaveURL(/\/s3$/);
  await expect(page.getByRole("link", { name: bucket })).toHaveCount(0);
});
