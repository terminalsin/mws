import { CreateBucketCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { expect, test, type Page } from "@playwright/test";

import { row, submit, sdk, unique } from "./helpers";

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

// Inline validation (packages/ui validation.ts): problems show on the field
// with repairs, and S3's own rejections land on the field they concern.

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => ({
    control: form.locator(`[name="${name}"]`),
    box: form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) }),
  });
  return { form, field };
}

const client = () => new S3Client({ ...sdk, forcePathStyle: true });

test("validation: bucket names are reshaped, and taken ones get the next free name", async ({ page }) => {
  const s3 = client();
  const taken = unique("dash-taken");
  await s3.send(new CreateBucketCommand({ Bucket: taken }));

  await page.goto("/s3");
  let { form, field } = await openSheet(page, "create-bucket");
  let name = field("name");
  // Bucket names are lowercase with "-": the fix reshapes what was typed.
  await name.control.fill("My Photos_2026");
  await name.control.blur();
  await expect(name.box).toHaveAttribute("data-invalid", "format");
  await name.box.getByRole("button", { name: /my-photos-2026/ }).click();
  await expect(name.control).toHaveValue("my-photos-2026");
  await expect(name.box).not.toHaveAttribute("data-invalid");

  // A bucket the page listed is flagged before submitting.
  await name.control.fill(taken);
  await name.control.blur();
  await expect(name.box).toHaveAttribute("data-invalid", "taken");
  await expect(name.box.getByRole("button", { name: /Use / })).toContainText(`${taken}-2`);

  // One created after the page loaded: S3's conflict lands on the field.
  const later = unique("dash-later");
  await page.goto("/s3");
  ({ form, field } = await openSheet(page, "create-bucket"));
  name = field("name");
  await s3.send(new CreateBucketCommand({ Bucket: later }));
  await name.control.fill(later);
  await form.locator('button[type="submit"]').click();
  await expect(name.box).toHaveAttribute("data-invalid", "taken");
  await expect(form.locator(".result.error")).toHaveCount(0);
  await name.box.getByRole("button", { name: /Use / }).click();
  await expect(name.control).toHaveValue(`${later}-2`);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByRole("link", { name: `${later}-2` })).toBeVisible();
});

test("validation: folders, content types, tags and policies", async ({ page }) => {
  const bucket = unique("dash-forms");
  const s3 = client();
  await s3.send(new CreateBucketCommand({ Bucket: bucket }));
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: "logs/", Body: "" }));
  await page.goto(`/s3/${bucket}`);

  // An existing folder is flagged, with the next free name.
  let { form, field } = await openSheet(page, "create-folder");
  const folder = field("name");
  await folder.control.fill("logs");
  await folder.control.blur();
  await expect(folder.box).toHaveAttribute("data-invalid", "taken");
  await expect(folder.box.getByRole("button", { name: /Use / })).toContainText("logs-2");
  await folder.control.fill("a//b");
  await folder.control.blur();
  await expect(folder.box).toHaveAttribute("data-invalid", "pattern");
  await page.keyboard.press("Escape");

  // A bare subtype suggests the full content type.
  ({ form, field } = await openSheet(page, "put-text-object"));
  const type = field("contentType");
  await type.control.fill("json");
  await type.control.blur();
  await expect(type.box).toHaveAttribute("data-invalid", "pattern");
  await type.box.getByRole("button", { name: /application\/json/ }).click();
  await expect(type.control).toHaveValue("application/json");
  await page.keyboard.press("Escape");

  // Pasted tags (colons, tabs, duplicates, reserved prefixes) become key=value lines.
  await page.goto(`/s3/${bucket}?tab=properties`);
  ({ form, field } = await openSheet(page, "edit-tags"));
  const tags = field("tags");
  await tags.control.fill("env: prod\nteam\tcore\naws:owner=me\nenv=staging");
  await tags.control.blur();
  await expect(tags.box).toHaveAttribute("data-invalid", "format");
  await tags.box.getByRole("button", { name: "Use key=value lines" }).click();
  await expect(tags.control).toHaveValue("team=core\nowner=me\nenv=staging");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByText("staging").first()).toBeVisible();

  // A hand-written policy is repaired in place.
  ({ form, field } = await openSheet(page, "edit-policy"));
  const policy = field("policy");
  await policy.control.fill(
    `{Version: '2012-10-17', Statement: [{Effect: 'Allow', Principal: {Service: 'logging.s3.amazonaws.com'}, Action: 's3:PutObject', Resource: 'arn:aws:s3:::${bucket}/*',}]}`,
  );
  await policy.control.blur();
  await expect(policy.box).toHaveAttribute("data-invalid", "format");
  await policy.box.getByRole("button", { name: "Fix the policy" }).click();
  await expect(policy.box).not.toHaveAttribute("data-invalid");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.locator('pre[aria-label="Bucket policy"]')).toContainText("s3:PutObject");
});
