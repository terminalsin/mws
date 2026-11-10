import { CreateAliasCommand, CreateKeyCommand, KMSClient, ListResourceTagsCommand } from "@aws-sdk/client-kms";
import { expect, test, type Page } from "@playwright/test";

import { sdk, submit, unique } from "./helpers";

const kms = new KMSClient(sdk);

test("KMS: create a key and round-trip data through it", async ({ page }) => {
  const alias = unique("dash-key");
  await page.goto("/kms");
  await submit(page, "create-key", { alias });
  await page.getByRole("link", { name: alias }).click();
  const result = await submit(page, "try-key", { plaintext: "round trip" });
  await expect(result).toContainText("→ round trip");
  await submit(page, "schedule-deletion", { days: "7" });
  await expect(page.getByTestId("cancel-deletion")).toBeVisible();
});

/** Open the sheet `testId` and return its form. */
async function sheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  return form;
}

const fieldOf = (page: Page, name: string) => page.locator("dialog[open] .field, .field").filter({ has: page.locator(`[name="${name}"]`) }).first();

test("KMS: alias fields repair reserved, taken and malformed names", async ({ page }) => {
  const existing = unique("dash-taken");
  const { KeyMetadata } = await kms.send(new CreateKeyCommand({}));
  await kms.send(new CreateAliasCommand({ AliasName: `alias/${existing}`, TargetKeyId: KeyMetadata!.KeyId }));

  await page.goto("/kms");
  const form = await sheet(page, "create-key");
  const alias = form.locator('input[name="alias"]');
  const field = fieldOf(page, "alias");

  // alias/aws/ belongs to AWS managed keys: offered without it.
  await alias.fill("alias/aws/orders");
  await alias.blur();
  await expect(field).toHaveAttribute("data-invalid", "reserved");
  await field.getByRole("button", { name: /Drop alias\/aws\// }).click();
  await expect(alias).toHaveValue("orders");
  await expect(field).not.toHaveAttribute("data-invalid");

  // Spaces are not allowed.
  await alias.fill("app data");
  await alias.blur();
  await expect(field).toHaveAttribute("data-invalid", "pattern");
  await field.getByRole("button", { name: /Replace spaces/ }).click();
  await expect(alias).toHaveValue("app-data");

  // Taken, with or without the prefix: the next free name is offered.
  await alias.fill(`alias/${existing}`);
  await alias.blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await alias.fill(existing);
  await alias.blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await field.getByRole("button", { name: /Use / }).click();
  await expect(alias).toHaveValue(`${existing}-2`);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByRole("link", { name: `${existing}-2` })).toBeVisible();
});

test("KMS: an alias taken after the page loaded lands on its field without creating a key", async ({ page }) => {
  const later = unique("dash-later");
  await page.goto("/kms");
  const form = await sheet(page, "create-key");
  const { KeyMetadata } = await kms.send(new CreateKeyCommand({}));
  await kms.send(new CreateAliasCommand({ AliasName: `alias/${later}`, TargetKeyId: KeyMetadata!.KeyId }));
  await form.locator('input[name="alias"]').fill(later);
  await form.locator('button[type="submit"]').click();
  const field = fieldOf(page, "alias");
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await expect(field.getByRole("button", { name: /Use / })).toContainText(`${later}-2`);
});

test("KMS: key forms repair days, JSON, tags and RSA-sized plaintext", async ({ page }) => {
  const { KeyMetadata } = await kms.send(new CreateKeyCommand({ KeySpec: "RSA_2048", KeyUsage: "ENCRYPT_DECRYPT" }));
  await page.goto(`/kms/key?id=${KeyMetadata!.KeyId}`);

  // RSA_2048 with OAEP SHA-256 takes at most 190 bytes.
  const text = page.getByTestId("try-key").locator('input[name="plaintext"]');
  const plain = fieldOf(page, "plaintext");
  await text.fill("x".repeat(200));
  await text.blur();
  await expect(plain).toHaveAttribute("data-invalid", "tooLong");
  await plain.getByRole("button", { name: /Shorten to 190/ }).click();
  await expect(text).toHaveValue("x".repeat(190));
  await page.getByTestId("try-key").locator('button[type="submit"]').click();
  await expect(page.getByTestId("try-key").getByRole("status")).toContainText("Round trip ok");

  // A hand-written policy is fixed in place.
  let form = await sheet(page, "edit-key-policy");
  const policy = form.locator('textarea[name="policy"]');
  await policy.fill("{'Version': '2012-10-17', Statement: [{'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'kms:*', 'Resource': '*'}],}");
  await policy.blur();
  const policyField = fieldOf(page, "policy");
  await expect(policyField).toHaveAttribute("data-invalid", "format");
  await policyField.getByRole("button", { name: /Fix the policy/ }).click();
  await expect(policyField).not.toHaveAttribute("data-invalid");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);

  // Tags written as "key: value" become key=value lines.
  await page.goto(`/kms/key?id=${KeyMetadata!.KeyId}&tab=tags`);
  form = await sheet(page, "edit-tags");
  const tags = form.locator('textarea[name="tags"]');
  await tags.fill("team: payments\nenv prod");
  await tags.blur();
  const tagsField = fieldOf(page, "tags");
  await expect(tagsField).toHaveAttribute("data-invalid", "format");
  await tagsField.getByRole("button", { name: /Use key=value lines/ }).click();
  await expect(tags).toHaveValue("team=payments\nenv=prod");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByText("payments", { exact: true })).toBeVisible();

  // KMS waits 7–30 days: out of range values are clamped.
  form = await sheet(page, "schedule-deletion");
  const days = form.locator('input[name="days"]');
  await days.fill("3");
  await days.blur();
  const daysField = fieldOf(page, "days");
  await expect(daysField).toHaveAttribute("data-invalid", "range");
  await daysField.getByRole("button", { name: /minimum, 7/ }).click();
  await expect(days).toHaveValue("7");
  await form.locator('button[type="submit"]').click();
  await expect(page.getByTestId("cancel-deletion")).toBeVisible();
});

test("KMS: ML-KEM and key agreement keys are listed and their try-its prove the key", async ({ page }) => {
  const kem = unique("dash-kem");
  const ecdh = unique("dash-ecdh");
  const a = await kms.send(new CreateKeyCommand({ KeySpec: "ML_KEM_768", KeyUsage: "ENCAPSULATE_DECAPSULATE" }));
  await kms.send(new CreateAliasCommand({ AliasName: `alias/${kem}`, TargetKeyId: a.KeyMetadata!.KeyId }));
  const b = await kms.send(new CreateKeyCommand({ KeySpec: "ECC_NIST_P256", KeyUsage: "KEY_AGREEMENT" }));
  await kms.send(new CreateAliasCommand({ AliasName: `alias/${ecdh}`, TargetKeyId: b.KeyMetadata!.KeyId }));

  await page.goto("/kms");
  await expect(page.getByRole("link", { name: kem })).toBeVisible();
  await page.getByRole("link", { name: kem }).click();
  await expect(page.getByRole("heading", { name: "Encapsulate and decapsulate" })).toBeVisible();
  await page.getByTestId("try-key").locator('button[type="submit"]').click();
  await expect(page.getByTestId("try-key").getByRole("status")).toContainText("same secret");

  await page.goto(`/kms/key?id=${b.KeyMetadata!.KeyId}`);
  await expect(page.getByRole("heading", { name: "Derive shared secret" })).toBeVisible();
  await page.getByTestId("try-key").locator('button[type="submit"]').click();
  await expect(page.getByTestId("try-key").getByRole("status")).toContainText("matches the peer");
  await page.goto(`/kms/key?id=${b.KeyMetadata!.KeyId}&tab=crypto`);
  await expect(page.locator("pre[aria-label='Public key']")).toContainText("BEGIN PUBLIC KEY");
});

test("KMS: removed tags are untagged, and grants are created and revoked", async ({ page }) => {
  const { KeyMetadata } = await kms.send(new CreateKeyCommand({ Tags: [{ TagKey: "team", TagValue: "payments" }, { TagKey: "env", TagValue: "prod" }] }));
  const id = KeyMetadata!.KeyId!;
  await page.goto(`/kms/key?id=${id}&tab=tags`);
  await submit(page, "edit-tags", { tags: "team=payments" });
  await expect(page.getByText("payments", { exact: true })).toBeVisible();
  await expect(page.getByText("prod", { exact: true })).toHaveCount(0);
  const { Tags } = await kms.send(new ListResourceTagsCommand({ KeyId: id }));
  expect(Tags?.map((t) => t.TagKey)).toEqual(["team"]);

  const name = unique("dash-grant");
  await page.goto(`/kms/key?id=${id}&tab=grants`);
  const form = await sheet(page, "create-grant");
  await form.locator('input[name="grantee"]').fill(`arn:aws:iam::${KeyMetadata!.AWSAccountId}:root`);
  await form.locator('input[name="name"]').fill(name);
  await form.locator('input[value="Decrypt"]').check();
  await form.locator('button[type="submit"]').click();
  await expect(form.getByRole("status")).toContainText("Created grant");
  await page.goto(`/kms/key?id=${id}&tab=grants`);
  const grant = page.locator("li.row").filter({ hasText: name });
  await expect(grant).toContainText("Decrypt");
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await grant.getByRole("button", { name: /Revoke grant/ }).click();
  await expect(page.locator("li.row").filter({ hasText: name })).toHaveCount(0);
});
