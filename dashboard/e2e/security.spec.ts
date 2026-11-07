import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("IAM: create a role and attach a managed policy", async ({ page }) => {
  const role = unique("dash-role");
  await page.goto("/security/iam?tab=roles");
  await submit(page, "create-role", { name: role });
  await page.getByRole("link", { name: role }).click();
  await expect(page.getByLabel("Trust policy")).toContainText("lambda.amazonaws.com");
  await submit(page, "attach-policy", { policyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" });
  await expect(page.getByRole("row").filter({ hasText: "ReadOnlyAccess" })).toBeVisible();
});

test("KMS: create a key and round-trip data through it", async ({ page }) => {
  const alias = `alias/${unique("dash-key")}`;
  await page.goto("/security/kms");
  await submit(page, "create-key", { alias });
  await expect(page.getByRole("row").filter({ hasText: alias })).toBeVisible();
  await page.getByTestId("try-key").locator("select").selectOption({ label: alias });
  const result = await submit(page, "try-key", { plaintext: "round trip" });
  await expect(result).toContainText("round trip");
});

test("Secrets Manager: create a secret and reveal it", async ({ page }) => {
  const name = unique("dash/secret");
  await page.goto("/security/secrets");
  await submit(page, "create-secret", { name, value: '{"password":"hunter2"}' });
  await page.getByRole("link", { name }).click();
  await expect(page.getByText("hunter2")).toHaveCount(0);
  await page.getByRole("link", { name: "Reveal value" }).click();
  await expect(page.getByLabel("Secret value")).toContainText("hunter2");
});

test("Parameter Store: SecureStrings stay encrypted until asked", async ({ page }) => {
  const name = `/${unique("dash")}/db/password`;
  await page.goto("/security/ssm");
  await submit(page, "put-parameter", { name, type: "SecureString", value: "s3cret" });
  const row = page.getByRole("row").filter({ hasText: name });
  await expect(row).toContainText("encrypted");
  await page.getByRole("link", { name: "Decrypt SecureStrings" }).click();
  await expect(page.getByRole("row").filter({ hasText: name })).toContainText("s3cret");
});
