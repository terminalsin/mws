import { CreateFilterCommand, DeleteFilterCommand, GuardDutyClient, ListDetectorsCommand } from "@aws-sdk/client-guardduty";
import { CreateBucketCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { expect, test, type Page } from "@playwright/test";

import { enableOnce, row, rowAction, sdk, unique } from "./helpers";

test("GuardDuty: sample findings are sorted by severity", async ({ page }) => {
  await page.goto("/guardduty");
  await enableOnce(page, "enable-guardduty", "sample-findings");
  await page.getByRole("button", { name: "Generate sample findings" }).click();
  await expect(page.locator("li.row").first()).toBeVisible();
  // The most severe come first.
  await expect(page.locator(".section-head h2").first()).toHaveText(/High|Critical/);
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

test("GuardDuty: a pasted list location is repaired to an s3:// URL", async ({ page }) => {
  const bucket = unique("gd-lists").toLowerCase();
  const s3 = new S3Client({ ...sdk, forcePathStyle: true });
  await s3.send(new CreateBucketCommand({ Bucket: bucket }));
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: "threats.txt", Body: "198.51.100.7\n" }));

  await page.goto("/guardduty/lists");
  await enableOnce(page, "enable-guardduty", "add-threat-open");
  const name = unique("Bad actors");
  const { form, field, input } = await openSheet(page, "add-threat");
  await input("name").fill(name);
  // An object ARN, as copied from the S3 console.
  await input("location").fill(`arn:aws:s3:::${bucket}/threats.txt`);
  await input("location").blur();
  await expect(field("location")).toHaveAttribute("data-invalid", "format");
  await field("location").getByRole("button", { name: /s3:\/\/ URL/ }).click();
  await expect(input("location")).toHaveValue(`s3://${bucket}/threats.txt`);
  await expect(field("location")).not.toHaveAttribute("data-invalid");

  // A bucket alone: the objects in it are suggested.
  await input("location").fill(`s3://${bucket}`);
  await input("location").blur();
  await field("location").getByRole("button", { name: /Did you mean/ }).click();
  await expect(input("location")).toHaveValue(`s3://${bucket}/threats.txt`);

  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, name)).toBeVisible();

  // The name is now taken for threat lists.
  const again = await openSheet(page, "add-threat");
  await again.input("name").fill(name);
  await again.input("name").blur();
  await expect(again.field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(again.field("name").getByRole("button", { name: /Use / })).toContainText(`${name}-2`);
  await page.keyboard.press("Escape");

  // Lists are capped per detector, so clean up.
  await rowAction(page, name, "Delete list");
  await expect(row(page, name)).toHaveCount(0);
});

test("GuardDuty: suppression rule names are fixed in place, conflicts land on the name", async ({ page }) => {
  const client = new GuardDutyClient(sdk);
  await page.goto("/guardduty/suppression");
  await enableOnce(page, "enable-guardduty", "create-suppression-rule-open");
  const detector = (await client.send(new ListDetectorsCommand({}))).DetectorIds![0];

  const rule = unique("noisy probes");
  let { form, field, input } = await openSheet(page, "create-suppression-rule");
  await input("name").fill(rule);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /Replace spaces/ }).click();
  const fixed = rule.replace(/\s+/g, "-");
  await expect(input("name")).toHaveValue(fixed);

  // Not a finding type: the expected shape is shown.
  await input("type").fill("port probe");
  await input("type").blur();
  await expect(field("type")).toHaveAttribute("data-invalid", "pattern");
  await expect(field("type")).toContainText("Recon:EC2/PortProbeUnprotectedPort");
  await input("type").fill("Recon:EC2/PortProbeUnprotectedPort");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, fixed)).toBeVisible();

  // Created elsewhere after the page loaded: GuardDuty's "same name already
  // exists" lands on the name field with the next free name.
  const later = unique("later");
  ({ form, field, input } = await openSheet(page, "create-suppression-rule"));
  await client.send(new CreateFilterCommand({ DetectorId: detector, Name: later, Action: "ARCHIVE", FindingCriteria: { Criterion: { type: { Equals: ["Recon:EC2/Portscan"] } } } }));
  await input("name").fill(later);
  await input("type").fill("Recon:EC2/Portscan");
  await form.locator('button[type="submit"]').click();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(input("name")).toHaveValue(`${later}-2`);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);

  for (const name of [fixed, later, `${later}-2`]) await client.send(new DeleteFilterCommand({ DetectorId: detector, FilterName: name }));
});
