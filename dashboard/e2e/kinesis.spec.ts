import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("Kinesis: put a record and read it back in the data viewer", async ({
  page,
}) => {
  const name = unique("dash-stream");
  await page.goto("/kinesis");
  await submit(page, "create-stream", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  // A new stream is CREATING for a moment, as in AWS.
  await expect(async () => {
    await page.reload();
    await expect(page.locator(".specs")).toContainText("active", {
      timeout: 1000,
    });
  }).toPass();
  await submit(page, "put-record", {
    key: "user-1",
    data: '{"clicked":"buy"}',
  });
  await page.reload();
  await expect(page.getByLabel("Records")).toContainText('{"clicked":"buy"}');
});

test("Kinesis: stream names and reshard targets are repaired in place", async ({
  page,
}) => {
  const name = unique("dash-shards");
  await page.goto("/kinesis");
  await submit(page, "create-stream", {
    name,
    mode: "PROVISIONED",
    shards: "1",
  });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(page.locator(".specs")).toContainText("active", {
      timeout: 1000,
    });
  }).toPass();

  // One call can at most double the open shards: 5 is clamped to 2.
  const sheet = page.locator("dialog[open]");
  await expect(async () => {
    if (!(await sheet.isVisible()))
      await page.getByTestId("reshard-open").first().click();
    await expect(sheet).toBeVisible({ timeout: 1000 });
  }).toPass();
  const shards = sheet.locator('input[name="shards"]');
  const field = sheet
    .locator(".field")
    .filter({ has: page.locator('input[name="shards"]') });
  await shards.fill("5");
  await shards.blur();
  await expect(field).toHaveAttribute("data-invalid", "range");
  await field.getByRole("button", { name: /maximum, 2/ }).click();
  await expect(shards).toHaveValue("2");
  await expect(field).not.toHaveAttribute("data-invalid");
  await page.keyboard.press("Escape");

  // Back on the list: a name with spaces gets a fix, a taken one the next free name.
  await page.goto("/kinesis");
  const form = sheet.getByTestId("create-stream").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible()))
      await page.getByTestId("create-stream-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const input = form.locator('input[name="name"]');
  const nameField = form
    .locator(".field")
    .filter({ has: page.locator('input[name="name"]') });
  await input.fill("click events");
  await input.blur();
  await expect(nameField).toHaveAttribute("data-invalid", "pattern");
  await nameField.getByRole("button", { name: /Replace spaces/ }).click();
  await expect(input).toHaveValue("click-events");
  await input.fill(name);
  await input.blur();
  await expect(nameField).toHaveAttribute("data-invalid", "taken");
  await nameField.getByRole("button", { name: /Use / }).click();
  await expect(input).toHaveValue(`${name}-2`);
});

async function activeStream(
  page: import("@playwright/test").Page,
  name: string,
  fields: Record<string, string> = {},
) {
  await page.goto("/kinesis");
  await submit(page, "create-stream", { name, ...fields });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(page.locator(".specs")).toContainText("active", {
      timeout: 1000,
    });
  }).toPass();
}

test("Kinesis: the viewer shows the newest records first and pages a shard", async ({
  page,
}) => {
  const name = unique("dash-newest");
  await activeStream(page, name, { mode: "PROVISIONED", shards: "1" });
  await submit(page, "put-records", {
    key: "k",
    data: Array.from({ length: 40 }, (_, i) => `{"n":${i}}`).join("\n"),
  });
  await page.reload();
  const records = page.getByLabel("Records");
  await expect(records.locator("li").first()).toContainText('{"n":39}');
  await expect(records).not.toContainText('{"n":0}');

  // One shard from the trim horizon, 25 at a time.
  await page.goto(
    `/kinesis/stream?name=${name}&shard=shardId-000000000000&from=trim`,
  );
  await expect(records.locator("li").first()).toContainText('{"n":0}');
  await page.getByTestId("load-more").click();
  await expect(records).toContainText('{"n":39}');
});

test("Kinesis: consumers, retention and tags", async ({ page }) => {
  const name = unique("dash-config");
  await activeStream(page, name);
  await page.getByRole("link", { name: /^Enhanced fan-out/ }).click();
  await submit(page, "register-consumer", { name: "analytics" });
  await expect(page.getByRole("list", { name: "Consumers" })).toContainText(
    "analytics",
  );

  await page.getByRole("link", { name: "Configuration" }).click();
  await submit(page, "edit-retention", { hours: "48" });
  await expect(page.locator(".facts")).toContainText("48 h");
  await submit(page, "add-stream-tags", { tags: "team=data" });
  await expect(page.getByRole("list", { name: "Tags" })).toContainText("team");
});
