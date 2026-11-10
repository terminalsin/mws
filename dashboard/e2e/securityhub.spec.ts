import { BatchImportFindingsCommand, CreateActionTargetCommand, SecurityHubClient } from "@aws-sdk/client-securityhub";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { expect, test, type Page } from "@playwright/test";

import { enableOnce, row, rowAction, sdk, unique } from "./helpers";

// Security Hub's forms validate in place: insights suggest the finding
// attribute meant, custom actions reshape names and ids to AWS's limits, and
// automation rule orders clamp to 1-1000.

async function open(page: Page, tab: string, testId: string) {
  await page.goto(`/securityhub?tab=${tab}`);
  await enableOnce(page, "enable-security-hub", `${testId}-open`);
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, input: (name: string) => form.locator(`[name="${name}"]`) };
}

test("Security Hub: an insight's group-by suggests the attribute meant", async ({ page }) => {
  const { form, field, input } = await open(page, "insights", "create-insight");
  const name = unique("dash-insight");
  await input("name").fill(name);
  await input("group").fill("resource id");
  await input("group").blur();
  await expect(field("group")).toHaveAttribute("data-invalid", "enum");
  await field("group").getByRole("button", { name: /Did you mean ResourceId/ }).click();
  await expect(input("group")).toHaveValue("ResourceId");
  await expect(field("group")).not.toHaveAttribute("data-invalid");
  await input("severity").selectOption("HIGH");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, name)).toContainText("ResourceId");
});

test("Security Hub: custom action names and ids are reshaped to fit", async ({ page }) => {
  const { form, field, input } = await open(page, "actions", "create-action");
  // Too long for a custom action name: shorten it in one click.
  await input("name").fill("Send to ticketing queue");
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "tooLong");
  await field("name").getByRole("button").first().click();
  await expect(field("name")).not.toHaveAttribute("data-invalid");
  expect((await input("name").inputValue()).length).toBeLessThanOrEqual(20);

  // Ids are letters and digits only.
  // Ends in a letter: a trailing digit would be counted up instead.
  const id = `dash${Date.now().toString(36)}x`;
  await input("id").fill(`${id.slice(0, 4)}-${id.slice(4)}`);
  await input("id").blur();
  await expect(field("id")).toHaveAttribute("data-invalid", "pattern");
  await field("id").getByRole("button").first().click();
  await expect(input("id")).toHaveValue(id);

  // Created by someone else meanwhile: the conflict lands on the id, with
  // the next free one.
  await new SecurityHubClient(sdk).send(new CreateActionTargetCommand({ Name: "Taken", Description: "Taken", Id: id }));
  await form.locator('button[type="submit"]').click();
  await expect(field("id")).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("id").getByRole("button", { name: /Use / }).click();
  await expect(input("id")).toHaveValue(`${id}2`);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, `${id}2`)).toBeVisible();
});

test("Security Hub: automation rule order clamps to its range", async ({ page }) => {
  const { form, field, input } = await open(page, "rules", "create-rule");
  const name = unique("dash-rule");
  await input("name").fill(name);
  await input("order").fill("0");
  await input("order").blur();
  await expect(field("order")).toHaveAttribute("data-invalid", "range");
  await field("order").getByRole("button").first().click();
  await expect(input("order")).toHaveValue("1");
  await input("severity").selectOption("LOW");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, name)).toBeVisible();
});

test("Security Hub: a finding's workflow, note and history change from its page", async ({ page }) => {
  await page.goto("/securityhub");
  await enableOnce(page, "enable-security-hub", "finding-filters");
  const account = (await new STSClient(sdk).send(new GetCallerIdentityCommand({}))).Account!;
  const product = `arn:aws:securityhub:${sdk.region}:${account}:product/${account}/default`;
  const id = unique("dash-finding");
  const title = unique("Dash open port");
  const now = new Date().toISOString();
  const imported = await new SecurityHubClient(sdk).send(
    new BatchImportFindingsCommand({
      Findings: [
        {
          SchemaVersion: "2018-10-08",
          Id: id,
          ProductArn: product,
          GeneratorId: "dash-e2e",
          AwsAccountId: account,
          Types: ["Software and Configuration Checks/Vulnerabilities"],
          CreatedAt: now,
          UpdatedAt: now,
          Severity: { Label: "HIGH" },
          Title: title,
          Description: "Port 22 open to the world",
          Resources: [{ Type: "AwsS3Bucket", Id: "arn:aws:s3:::dash-e2e-bucket" }],
        },
      ],
    }),
  );
  expect(imported.FailedCount).toBe(0);

  // Open findings list it under High, with a link to its page.
  await page.goto("/securityhub?severity=HIGH");
  await expect(row(page, title)).toBeVisible();
  await page.goto(`/securityhub/finding?id=${encodeURIComponent(id)}&product=${encodeURIComponent(product)}`);
  await expect(page.getByRole("heading", { name: title })).toBeVisible();
  await expect(page.locator('a[href^="/s3/bucket"]').or(page.getByText("arn:aws:s3:::dash-e2e-bucket")).first()).toBeVisible();

  await page.getByTestId("workflow-resolved").locator('button[type="submit"]').click();
  await expect(page.getByTestId("workflow-new")).toBeAttached();
  await expect(page.locator(".status").filter({ hasText: /^resolved$/i })).toBeVisible();

  const note = unique("Closed by the firewall team");
  await page.getByTestId("update-finding-open").click();
  const form = page.locator("dialog[open]").getByTestId("update-finding").and(page.locator("form"));
  await form.locator('[name="note"]').fill(note);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.locator(".banner").filter({ hasText: note })).toBeVisible();
  await expect(page.getByLabel("History").getByText(/Workflow/).first()).toBeVisible();

  // Resolved findings leave the default view and show under Resolved.
  await page.goto("/securityhub?severity=HIGH");
  await expect(row(page, title)).toHaveCount(0);
  await page.goto("/securityhub?workflow=RESOLVED&severity=HIGH");
  await expect(row(page, title)).toBeVisible();
});

test("Security Hub: a standard's control is disabled with a reason and enabled again", async ({ page }) => {
  await page.goto("/securityhub");
  await enableOnce(page, "enable-security-hub", "finding-filters");
  await page.goto("/securityhub?tab=standards");
  const link = page.locator('a[href^="/securityhub/standard?arn="]').first();
  await expect(link).toBeAttached();
  await page.goto((await link.getAttribute("href"))!);
  const controls = page.getByLabel("Controls");
  const target = controls.locator("li.row").filter({ has: page.getByTestId("disable-control-open") }).last();
  const title = ((await target.locator(".row-title").first().textContent()) ?? "").trim();
  const controlId = title.split(" ")[0];
  const reason = unique("Not applicable here");
  await target.getByTestId("disable-control-open").click();
  const form = page.locator("dialog[open]").getByTestId("disable-control").and(page.locator("form"));
  await form.locator('[name="reason"]').fill(reason);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, reason)).toBeVisible();
  await rowAction(page, reason, `Enable ${controlId}`);
  await expect(row(page, reason)).toHaveCount(0);
});
