import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("IAM: create a role, attach a managed policy, group roles by who trusts them", async ({ page }) => {
  const role = unique("dash-role");
  await page.goto("/security/iam?tab=roles");
  await submit(page, "create-role", { name: role });
  await page.getByRole("link", { name: role }).click();
  await expect(page.locator("pre[aria-label='Trust policy']")).toContainText("lambda.amazonaws.com");
  await submit(page, "attach-policy", { policyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" });
  await expect(row(page, "ReadOnlyAccess")).toBeVisible();

  await page.goto("/security/iam?tab=roles");
  await expect(row(page, role)).toContainText("lambda.amazonaws.com");
});

test("IAM: a user gets an access key, shown once", async ({ page }) => {
  const user = unique("dash-user");
  await page.goto("/security/iam");
  await submit(page, "create-user", { name: user });
  await page.getByRole("link", { name: user }).click();
  const result = await submit(page, "create-access-key");
  await expect(result).toContainText("AWS_SECRET_ACCESS_KEY=");
});

test("KMS: create a key and round-trip data through it", async ({ page }) => {
  const alias = unique("dash-key");
  await page.goto("/security/kms");
  await submit(page, "create-key", { alias });
  await page.getByRole("link", { name: alias }).click();
  const result = await submit(page, "try-key", { plaintext: "round trip" });
  await expect(result).toContainText("→ round trip");
  await submit(page, "schedule-deletion", { days: "7" });
  await expect(page.getByTestId("cancel-deletion")).toBeVisible();
});

test("Secrets Manager: create a secret and reveal it", async ({ page }) => {
  const name = unique("dash/secret");
  await page.goto("/security/secrets");
  await submit(page, "create-secret", { name, value: '{"password":"hunter2"}' });
  await page.getByRole("link", { name }).click();
  await expect(page.getByText("hunter2")).toHaveCount(0);
  await page.getByRole("link", { name: "Reveal value" }).click();
  await expect(page.locator("pre[aria-label='Secret value']")).toContainText("hunter2");
});

test("Parameter Store: browse by path; SecureStrings stay hidden until asked", async ({ page }) => {
  const root = unique("dash");
  const name = `/${root}/db/password`;
  await page.goto("/security/ssm");
  await submit(page, "put-parameter", { name, type: "SecureString", value: "s3cret" });
  await page.goto(`/security/ssm?path=${encodeURIComponent(`/${root}/db/`)}`);
  await expect(row(page, "password")).not.toContainText("s3cret");
  await page.getByRole("link", { name: "Reveal values" }).click();
  await expect(row(page, "password")).toContainText("s3cret");
});
