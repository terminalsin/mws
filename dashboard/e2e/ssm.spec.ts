import { GetParameterHistoryCommand, PutParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

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

async function openSheet(page: Page) {
  await page.goto("/ssm");
  const form = page.locator("dialog[open]").getByTestId("put-parameter").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("put-parameter-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const name = form.locator('input[name="name"]');
  const field = form.locator(".field").filter({ has: page.locator('input[name="name"]') });
  return { form, name, field };
}

test("Parameter Store: names are repaired in place", async ({ page }) => {
  const root = unique("dash");
  const { form, name, field } = await openSheet(page);

  // A path without its leading slash.
  await name.fill(`${root}/db`);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "pattern");
  await field.getByRole("button", { name: /Start with/ }).click();
  await expect(name).toHaveValue(`/${root}/db`);
  await expect(field).not.toHaveAttribute("data-invalid");

  // Under the reserved aws prefix, with a space.
  await name.fill(`/aws/${root}/db host`);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "reserved");
  await field.getByRole("button", { name: /Drop/ }).click();
  await expect(name).toHaveValue(`/${root}/db-host`);
  await expect(field).not.toHaveAttribute("data-invalid");

  // An empty value blocks the save on its own field.
  await form.locator('button[type="submit"]').click();
  const value = form.locator(".field").filter({ has: page.locator('textarea[name="value"]') });
  await expect(value).toHaveAttribute("data-invalid", "required");
  await expect(form.locator('textarea[name="value"]')).toBeFocused();
});

test("Parameter Store: existing names suggest the next free one", async ({ page }) => {
  const client = new SSMClient(sdk);
  const taken = `/${unique("dash")}/db`;
  await client.send(new PutParameterCommand({ Name: taken, Value: "x", Type: "String" }));

  // Known when the page loaded: flagged before saving.
  let { form, name, field } = await openSheet(page);
  await name.fill(taken);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(field.getByRole("button", { name: /Use / })).toContainText(`${taken}-2`);

  // Created after the page loaded: ParameterAlreadyExists lands on the name.
  const later = `/${unique("dash")}/db`;
  ({ form, name, field } = await openSheet(page));
  await client.send(new PutParameterCommand({ Name: later, Value: "x", Type: "String" }));
  await name.fill(later);
  await form.locator('textarea[name="value"]').fill("y");
  await form.locator('button[type="submit"]').click();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(form.locator(".result.error")).toHaveCount(0);
  await field.getByRole("button", { name: /Use / }).click();
  await expect(name).toHaveValue(`${later}-2`);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
});

test("Parameter Store: a parameter's page shows its history and labels a version", async ({ page }) => {
  const ssm = new SSMClient(sdk);
  const name = `/${unique("dash")}/feature`;
  await ssm.send(new PutParameterCommand({ Name: name, Type: "String", Value: "off" }));
  await ssm.send(new PutParameterCommand({ Name: name, Type: "String", Value: "on", Overwrite: true }));
  await page.goto(`/ssm/parameter?name=${encodeURIComponent(name)}&tab=history`);
  await expect(page.locator("li.row")).toHaveCount(2);
  await submit(page, "label-1", { labels: "stable" });
  await expect(page.locator("li.row").filter({ hasText: "stable" })).toBeVisible();
  const { Parameters } = await ssm.send(new GetParameterHistoryCommand({ Name: name }));
  expect(Parameters?.find((p) => p.Version === 1)?.Labels).toEqual(["stable"]);
});

test("Systems Manager: create a document, a maintenance window, an association and an OpsItem", async ({ page }) => {
  test.setTimeout(120_000);
  const doc = unique("Dash-Doc");
  await page.goto("/ssm/documents");
  await submit(page, "create-document", { name: doc });
  await expect(page).toHaveURL(/\/ssm\/document\?/);
  await expect(page.getByRole("heading", { name: doc })).toBeVisible();

  const window = unique("dash-window");
  await page.goto("/ssm/windows");
  await submit(page, "create-window", { name: window });
  await expect(page.getByRole("heading", { name: window })).toBeVisible();
  await submit(page, "register-target", { targets: "tag:env=dash", name: "dash-targets" });
  await expect(page.locator("li.row").filter({ hasText: "dash-targets" })).toBeVisible();

  const association = unique("dash-assoc");
  await page.goto("/ssm/associations");
  await submit(page, "create-association", { name: association, targets: "tag:env=dash", schedule: "rate(30 minutes)", parameters: "commands=uptime" });
  await expect(page).toHaveURL(/\/ssm\/association\?/);
  await expect(page.getByRole("heading", { name: association })).toBeVisible();

  const title = unique("dash-ops");
  await page.goto("/ssm/opsitems");
  await submit(page, "create-opsitem", { title, description: "disk full" });
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  await page.getByTestId("opsitem-resolve").locator('button[type="submit"]').click();
  await expect(page.getByText("Resolved", { exact: true }).first()).toBeVisible();
});
