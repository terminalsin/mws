import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("create a bucket, write, read, download and delete objects", async ({ page, request }) => {
  const bucket = unique("dash-bucket");
  await page.goto("/storage/s3");
  await submit(page, "create-bucket", { name: bucket });
  await page.getByRole("link", { name: bucket }).click();
  await expect(page.getByRole("heading", { level: 1, name: bucket })).toBeVisible();

  await submit(page, "put-text-object", { key: "docs/hello.json", body: '{"hello":"world"}', contentType: "application/json" });
  await page.getByRole("link", { name: /docs\// }).click();
  await page.getByRole("link", { name: "hello.json" }).click();
  await expect(page.getByLabel("Object preview")).toContainText('"hello": "world"');

  const download = await request.get(`/storage/api/object?bucket=${bucket}&key=docs/hello.json`);
  expect(await download.json()).toEqual({ hello: "world" });

  await page.goto(`/storage/s3/${bucket}`);
  const upload = page.getByTestId("upload-object");
  await upload.locator('input[type="file"]').setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("uploaded") });
  await upload.getByRole("button", { name: "Upload" }).click();
  await expect(upload.getByRole("status")).toContainText("Uploaded notes.txt");
  await expect(page.getByRole("link", { name: "notes.txt" })).toBeVisible();

  await page.getByRole("link", { name: "Properties" }).click();
  await expect(page.getByText("Versioning")).toBeVisible();
  await page.getByLabel("Delete every object and version first").check();
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Delete bucket" }).click();
  await expect(page).toHaveURL(/\/storage\/s3$/);
  await expect(page.getByRole("link", { name: bucket })).toHaveCount(0);
});
