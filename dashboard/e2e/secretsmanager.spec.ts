import { CreateSecretCommand, DescribeSecretCommand, GetResourcePolicyCommand, PutSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { expect, test, type Page } from "@playwright/test";

import { sdk, submit, unique } from "./helpers";

test("Secrets Manager: create a secret and reveal it", async ({ page }) => {
  const name = unique("dash/secret");
  await page.goto("/secrets");
  await submit(page, "create-secret", { name, value: '{"password":"hunter2"}' });
  await page.getByRole("link", { name }).click();
  await expect(page.getByText("hunter2")).toHaveCount(0);
  await page.getByRole("link", { name: "Reveal value" }).click();
  await expect(page.locator("pre[aria-label='Secret value']")).toContainText("hunter2");
});

// Inline validation (docs/dashboard.md, "Form validation and repairs").

async function sheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, control: (name: string) => form.locator(`[name="${name}"]`) };
}

test("Secrets Manager: create-secret fields repair names, JSON values and KMS keys", async ({ page }) => {
  await page.goto("/secrets");
  const { form, field, control } = await sheet(page, "create-secret");

  const name = unique("Dash Secret");
  await control("name").fill(name);
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /Replace spaces/ }).click();
  await expect(control("name")).toHaveValue(name.replace(/\s+/g, "-"));
  await expect(field("name")).not.toHaveAttribute("data-invalid");

  // Plain text is fine; something that starts like JSON must be JSON.
  await control("value").fill("{'username': 'app', 'password': 'hunter2',}");
  await control("value").blur();
  await expect(field("value")).toHaveAttribute("data-invalid", "format");
  await field("value").getByRole("button", { name: /Fix the JSON/ }).click();
  expect(JSON.parse(await control("value").inputValue())).toEqual({ username: "app", password: "hunter2" });

  // An empty value blocks the submission and offers a generated password.
  const json = await control("value").inputValue();
  await control("value").fill("");
  await form.locator('button[type="submit"]').click();
  await expect(field("value")).toHaveAttribute("data-invalid", "required");
  await expect(field("value").getByRole("button", { name: /Generate/ })).toBeVisible();
  await control("value").fill(json);

  // A key Secrets Manager can't use comes back on the KMS key field.
  await control("kmsKeyId").fill("alias/no-such-key");
  await form.locator('button[type="submit"]').click();
  await expect(field("kmsKeyId")).toHaveAttribute("data-invalid", /.+/);
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await control("kmsKeyId").fill("");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByRole("link", { name: name.replace(/\s+/g, "-") })).toBeVisible();
});

test("Secrets Manager: a name taken after the page loaded suggests the next free one", async ({ page }) => {
  await page.goto("/secrets");
  const { form, field, control } = await sheet(page, "create-secret");
  const name = unique("dash/taken");
  await new SecretsManagerClient(sdk).send(new CreateSecretCommand({ Name: name, SecretString: "x" }));
  await control("name").fill(name);
  await control("value").fill("s3cret");
  await form.locator('button[type="submit"]').click();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(control("name")).toHaveValue(`${name}-2`);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByRole("link", { name: `${name}-2` })).toBeVisible();
});

test("Secrets Manager: rotation fields expand function names and clamp days", async ({ page }) => {
  const name = unique("dash/rotate");
  const out = await new SecretsManagerClient(sdk).send(new CreateSecretCommand({ Name: name, SecretString: "x" }));
  await page.goto(`/secrets/secret?id=${encodeURIComponent(out.ARN!)}`);
  const { field, control } = await sheet(page, "rotate-secret");

  await control("lambda").fill("rotate-db");
  await control("lambda").blur();
  await expect(field("lambda")).toHaveAttribute("data-invalid", "format");
  await field("lambda").getByRole("button", { name: /Expand to an ARN/ }).click();
  await expect(control("lambda")).toHaveValue(/^arn:aws:lambda:[a-z0-9-]+:\d{12}:function:rotate-db$/);

  await control("days").fill("2000");
  await control("days").blur();
  await expect(field("days")).toHaveAttribute("data-invalid", "range");
  await field("days").getByRole("button").first().click();
  await expect(control("days")).toHaveValue("1000");
});

test("Secrets Manager: edit, move AWSCURRENT back, attach a policy and untag", async ({ page }) => {
  const sm = new SecretsManagerClient(sdk);
  const name = unique("dash/versions");
  const { ARN } = await sm.send(new CreateSecretCommand({ Name: name, SecretString: "first", Tags: [{ Key: "team", Value: "a" }, { Key: "env", Value: "b" }] }));
  const second = await sm.send(new PutSecretValueCommand({ SecretId: ARN, SecretString: "second" }));
  const self = `/secrets/secret?id=${encodeURIComponent(ARN!)}`;

  await page.goto(self);
  await submit(page, "edit-secret", { description: "rotated by hand" });
  expect((await sm.send(new DescribeSecretCommand({ SecretId: ARN }))).Description).toBe("rotated by hand");

  await page.goto(`${self}&tab=versions`);
  const previous = page.locator("li.row").filter({ hasText: "AWSPREVIOUS" });
  await expect(previous).toBeVisible();
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await previous.getByRole("button", { name: /^Make .* current$/ }).click();
  await expect(page.locator("li.row").filter({ hasText: second.VersionId! })).toContainText("AWSPREVIOUS");
  const stages = (await sm.send(new DescribeSecretCommand({ SecretId: ARN }))).VersionIdsToStages!;
  expect(stages[second.VersionId!]).toEqual(["AWSPREVIOUS"]);

  await page.goto(`${self}&tab=permissions`);
  await submit(page, "edit-policy");
  expect((await sm.send(new GetResourcePolicyCommand({ SecretId: ARN }))).ResourcePolicy).toContain("secretsmanager:GetSecretValue");

  await page.goto(`${self}&tab=tags`);
  await submit(page, "edit-tags", { tags: "team=a" });
  expect((await sm.send(new DescribeSecretCommand({ SecretId: ARN }))).Tags?.map((t) => t.Key)).toEqual(["team"]);
});
