import {
  CreateStreamCommand,
  DescribeStreamSummaryCommand,
  KinesisClient,
} from "@aws-sdk/client-kinesis";
import { expect, test, type Page } from "@playwright/test";

import { sdk, submit, unique } from "./helpers";

async function openCreate(page: Page) {
  await page.goto("/firehose");
  const form = page
    .locator("dialog[open]")
    .getByTestId("create-delivery-stream")
    .and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible()))
      await page.getByTestId("create-delivery-stream-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) =>
    form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return {
    form,
    field,
    input: (name: string) => form.locator(`[name="${name}"]`),
  };
}

async function kinesisStream(prefix: string) {
  const name = unique(prefix);
  const kinesis = new KinesisClient(sdk);
  await kinesis.send(
    new CreateStreamCommand({ StreamName: name, ShardCount: 1 }),
  );
  const arn = (
    await kinesis.send(new DescribeStreamSummaryCommand({ StreamName: name }))
  ).StreamDescriptionSummary!.StreamARN!;
  return { name, arn };
}

test("Firehose: a stream with its bucket and role made automatically", async ({
  page,
}) => {
  const name = unique("dash-fh");
  const { form, input } = await openCreate(page);
  await input("name").fill(name);
  for (const pick of ["destination-bucket", "firehose-role"])
    await form
      .getByTestId(pick)
      .getByRole("button", { name: "Create automatically" })
      .click();
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator("main")).toContainText(/firehose-\d{12}-/);
});

test("Firehose: fields repair names, intervals and bare source streams in place", async ({
  page,
}) => {
  const source = await kinesisStream("dash-fh-src");
  const { form, field, input } = await openCreate(page);

  // The model's name pattern: spaces become hyphens.
  const name = unique("Dash Clicks");
  await input("name").fill(name);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name")
    .getByRole("button", { name: /Replace spaces/ })
    .click();
  await expect(input("name")).toHaveValue(name.replace(/\s+/g, "-"));
  await expect(field("name")).not.toHaveAttribute("data-invalid");

  // Buffering interval is 0–900 s: clamped to the maximum.
  await input("interval").fill("1200");
  await input("interval").blur();
  await expect(field("interval")).toHaveAttribute("data-invalid", "range");
  await field("interval")
    .getByRole("button", { name: /maximum/ })
    .click();
  await expect(input("interval")).toHaveValue("900");

  // A bare stream name expands to its ARN in this account and region.
  await input("source").fill(source.name);
  await input("source").blur();
  await expect(field("source")).toHaveAttribute("data-invalid", "format");
  await field("source")
    .getByRole("button", {
      name: new RegExp(`Expand to an ARN|Use ${source.name}`),
    })
    .first()
    .click();
  await expect(input("source")).toHaveValue(source.arn);

  for (const pick of ["destination-bucket", "firehose-role"])
    await form
      .getByTestId(pick)
      .getByRole("button", { name: "Create automatically" })
      .click();
  await form.locator('button[type="submit"]').click();
  await expect(
    page.getByRole("heading", { level: 1, name: name.replace(/\s+/g, "-") }),
  ).toBeVisible();
  await expect(page.locator(".flow")).toContainText(source.name);
});

test("Firehose: taken names and unreachable sources land on their fields", async ({
  page,
}) => {
  const taken = unique("dash-fh-taken");
  let { form, input } = await openCreate(page);
  await input("name").fill(taken);
  for (const pick of ["destination-bucket", "firehose-role"])
    await form
      .getByTestId(pick)
      .getByRole("button", { name: "Create automatically" })
      .click();
  await form.locator('button[type="submit"]').click();
  await expect(
    page.getByRole("heading", { level: 1, name: taken }),
  ).toBeVisible();

  const source = await kinesisStream("dash-fh-known");
  let field;
  ({ form, field, input } = await openCreate(page));
  // Known when the page loaded: flagged before submitting.
  await input("name").fill(taken);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(
    field("name").getByRole("button", { name: /Use / }),
  ).toContainText(`${taken}-2`);

  // A typo in the source ARN: MWS can't read the stream, and the field
  // offers the stream it most likely meant.
  await input("name").fill(unique("dash-fh-typo"));
  await input("source").fill(`${source.arn}x`);
  for (const pick of ["destination-bucket", "firehose-role"])
    await form
      .getByTestId(pick)
      .getByRole("button", { name: "Create automatically" })
      .click();
  await form.locator('button[type="submit"]').click();
  await expect(field("source")).toHaveAttribute("data-invalid", "missing");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("source")
    .getByRole("button", { name: `Did you mean ${source.arn}?` })
    .click();
  await expect(input("source")).toHaveValue(source.arn);
});

test("Firehose: an empty record is flagged on the record", async ({ page }) => {
  const name = unique("dash-fh-rec");
  const { form, input } = await openCreate(page);
  await input("name").fill(name);
  for (const pick of ["destination-bucket", "firehose-role"])
    await form
      .getByTestId(pick)
      .getByRole("button", { name: "Create automatically" })
      .click();
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();

  const sheet = page
    .locator("dialog[open]")
    .getByTestId("put-firehose-record")
    .and(page.locator("form"));
  await expect(async () => {
    if (!(await sheet.isVisible()))
      await page.getByTestId("put-firehose-record-open").first().click();
    await expect(sheet).toBeVisible({ timeout: 1000 });
  }).toPass();
  const record = sheet.locator('textarea[name="data"]');
  const box = sheet
    .locator(".field")
    .filter({ has: page.locator(`textarea[name="data"]`) });
  await record.fill("");
  await sheet.locator('button[type="submit"]').click();
  await expect(box).toHaveAttribute("data-invalid", "required");
  await expect(record).toBeFocused();
});

test("Firehose: an HTTP endpoint stream, its full configuration and an edit", async ({
  page,
}) => {
  const name = unique("dash-fh-http");
  const { form, input } = await openCreate(page);
  await input("name").fill(name);
  await input("destination").selectOption("http");
  await input("url").fill("https://example.com/ingest");
  await input("endpointName").fill("Example");
  for (const pick of ["destination-bucket", "firehose-role"])
    await form
      .getByTestId(pick)
      .getByRole("button", { name: "Create automatically" })
      .click();
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".facts")).toContainText(
    "https://example.com/ingest",
  );
  await expect(page.locator(".facts")).toContainText("Backup bucket");

  await expect(async () => {
    await page.reload();
    await expect(page.locator(".specs")).toContainText("active", {
      timeout: 1000,
    });
  }).toPass();
  await submit(page, "edit-destination", {
    url: "https://example.com/v2",
    retry: "60",
  });
  await expect(page.locator(".facts")).toContainText("https://example.com/v2");
  await expect(page.locator(".specs")).toContainText("v2");
});

test("Firehose: S3 delivery shows up under Destination objects", async ({
  page,
}) => {
  const name = unique("dash-fh-obj");
  const { form, input } = await openCreate(page);
  await input("name").fill(name);
  await input("prefix").fill(`${name}/`);
  await input("interval").fill("0");
  for (const pick of ["destination-bucket", "firehose-role"])
    await form
      .getByTestId(pick)
      .getByRole("button", { name: "Create automatically" })
      .click();
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(page.locator(".specs")).toContainText("active", {
      timeout: 1000,
    });
  }).toPass();
  await submit(page, "put-record-batch", { data: '{"a":1}\n{"a":2}' });
  await expect(async () => {
    await page.goto(`/firehose/stream?name=${name}&tab=objects`);
    await expect(
      page.getByLabel("Delivered objects").locator("li"),
    ).not.toHaveCount(0, { timeout: 1000 });
  }).toPass({ timeout: 60_000 });
});
