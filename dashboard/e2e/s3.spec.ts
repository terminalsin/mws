import { CreateBucketCommand, DeleteObjectCommand, GetBucketCorsCommand, PutBucketVersioningCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { CreateQueueCommand, SQSClient } from "@aws-sdk/client-sqs";
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
  await expect(page.getByText("staging").filter({ visible: true }).first()).toBeVisible();

  // A hand-written policy is repaired in place.
  await page.goto(`/s3/${bucket}?tab=permissions`);
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

test("objects page past 1,000 keys with a continuation token", async ({ page }) => {
  test.setTimeout(180_000);
  const s3 = client();
  const bucket = unique("dash-many");
  await s3.send(new CreateBucketCommand({ Bucket: bucket }));
  const keys = Array.from({ length: 1005 }, (_, i) => `k${String(i).padStart(4, "0")}.txt`);
  for (let i = 0; i < keys.length; i += 50) await Promise.all(keys.slice(i, i + 50).map((Key) => s3.send(new PutObjectCommand({ Bucket: bucket, Key, Body: "x" }))));
  await page.goto(`/s3/${bucket}`);
  await expect(page.locator("a.row-main", { hasText: "k0999.txt" })).toBeVisible();
  await expect(page.locator("a.row-main", { hasText: "k1004.txt" })).toHaveCount(0);
  await page.getByTestId("load-more").click();
  await expect(page.locator("a.row-main", { hasText: "k1004.txt" })).toBeVisible();
  await expect(page.locator("a.row-main", { hasText: "k0000.txt" })).toHaveCount(0);
});

test("versions: delete markers, the null version, undelete and version downloads", async ({ page, request }) => {
  const s3 = client();
  const bucket = unique("dash-versions");
  await s3.send(new CreateBucketCommand({ Bucket: bucket }));
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: "doc.txt", Body: "first", ContentType: "text/plain" }));
  await s3.send(new PutBucketVersioningCommand({ Bucket: bucket, VersioningConfiguration: { Status: "Enabled" } }));
  const second = await s3.send(new PutObjectCommand({ Bucket: bucket, Key: "doc.txt", Body: "second", ContentType: "text/plain" }));
  await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: "doc.txt" }));

  // The plain listing no longer shows it; "Show versions" lists both versions and the marker.
  await page.goto(`/s3/${bucket}`);
  await expect(page.locator("a.row-main", { hasText: "doc.txt" })).toHaveCount(0);
  await page.getByTestId("show-versions").click();
  await expect(row(page, "Delete marker")).toBeVisible();
  await expect(row(page, /\bnull\b/)).toBeVisible();

  // The null version downloads by its id.
  const old = await request.get(`/api/s3/object?bucket=${bucket}&key=doc.txt&version=null`);
  expect(await old.text()).toBe("first");

  // The object page says it is deleted; removing the marker brings back the second version.
  await page.goto(`/s3/${bucket}/object?key=doc.txt`);
  await expect(page.getByTestId("deleted-banner")).toBeVisible();
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await row(page, "Delete marker").getByRole("button", { name: /Remove delete marker/ }).click();
  await expect(page.getByTestId("deleted-banner")).toHaveCount(0);
  await expect(page.getByLabel("Object preview")).toContainText("second");

  // Make the null version current again.
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await row(page, /^null/).getByRole("button", { name: /Make version null current/ }).click();
  await expect(page.getByLabel("Object preview")).toContainText("first");
  // Viewing the second version by id.
  await page.goto(`/s3/${bucket}/object?key=doc.txt&version=${second.VersionId}`);
  await expect(page.getByLabel("Object preview")).toContainText("second");
});

test("event notifications link to their queue; lifecycle rules and CORS are editable", async ({ page }) => {
  const s3 = client();
  const bucket = unique("dash-config");
  await s3.send(new CreateBucketCommand({ Bucket: bucket }));
  const queue = unique("dash-events");
  const account = "123456789012";
  const arn = `arn:aws:sqs:${sdk.region}:${account}:${queue}`;
  // S3 checks that the queue lets it send, as AWS does.
  const Policy = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "s3.amazonaws.com" }, Action: "sqs:SendMessage", Resource: arn }] });
  await new SQSClient(sdk).send(new CreateQueueCommand({ QueueName: queue, Attributes: { Policy } }));

  await page.goto(`/s3/${bucket}?tab=properties`);
  await submit(page, "create-notification", { id: "to-queue", type: "sqs", arn, prefix: "in/" });
  const n = row(page, "to-queue");
  await expect(n).toContainText("s3:ObjectCreated:*");
  await expect(n.getByRole("link", { name: queue })).toHaveAttribute("href", `/sqs/${queue}`);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await n.getByRole("button", { name: "Delete to-queue" }).click();
  await expect(row(page, "to-queue")).toHaveCount(0);

  await page.goto(`/s3/${bucket}?tab=management`);
  await submit(page, "create-lifecycle-rule", { id: "expire-logs", prefix: "logs/", expire: "30" });
  const rule = row(page, "expire-logs");
  await expect(rule).toContainText("expire after 30d");
  await expect(rule).toContainText("Enabled");
  await rule.getByRole("button", { name: "Disable expire-logs" }).click();
  await expect(row(page, "expire-logs")).toContainText("Disabled");
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await row(page, "expire-logs").getByRole("button", { name: "Delete rule expire-logs" }).click();
  await expect(row(page, "expire-logs")).toHaveCount(0);

  await page.goto(`/s3/${bucket}?tab=permissions`);
  await submit(page, "edit-cors", { cors: JSON.stringify([{ AllowedMethods: ["GET"], AllowedOrigins: ["https://example.com"] }]) });
  await expect(page.getByLabel("CORS rules", { exact: true })).toContainText("https://example.com");
  const cors = await s3.send(new GetBucketCorsCommand({ Bucket: bucket }));
  expect(cors.CORSRules?.[0]?.AllowedOrigins).toEqual(["https://example.com"]);
});

test("access points: create on a bucket, edit the policy, delete; account Block Public Access shows", async ({ page }) => {
  const s3 = client();
  const bucket = unique("dash-ap");
  await s3.send(new CreateBucketCommand({ Bucket: bucket }));
  const name = `ap-${Date.now().toString(36)}`;
  await page.goto(`/s3/${bucket}?tab=access-points`);
  await submit(page, "create-access-point", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".subtitle")).toContainText(`:accesspoint/${name}`);
  await submit(page, "edit-ap-policy");
  await expect(page.locator('pre[aria-label="Access point policy"]')).toContainText("s3:GetObject");

  await page.goto("/s3?tab=access-points");
  await expect(row(page, name)).toContainText(bucket);
  await page.goto(`/s3/${bucket}/access-point?name=${name}`);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-access-point").locator('button[type="submit"]').click();
  await expect(page).toHaveURL(new RegExp(`/s3/${bucket}\\?tab=access-points`));
  await expect(row(page, name)).toHaveCount(0);

  // Account-wide settings are shared by every test: only look.
  await page.goto("/s3?tab=block-public-access");
  await expect(page.getByText("Block all public access")).toBeVisible();
});
