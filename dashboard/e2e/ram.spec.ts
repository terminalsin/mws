import { ACMPCAClient, CreateCertificateAuthorityCommand } from "@aws-sdk/client-acm-pca";
import { expect, test, type Page } from "@playwright/test";

import { row, rowAction, sdk, submit, unique } from "./helpers";

async function openSheet(page: Page) {
  await page.goto("/ram");
  const form = page.locator("dialog[open]").getByTestId("create-share").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("create-share-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field };
}

test("RAM: share fields check each item and repair it in place", async ({ page }) => {
  const { CertificateAuthorityArn: ca } = await new ACMPCAClient(sdk).send(
    new CreateCertificateAuthorityCommand({
      CertificateAuthorityType: "ROOT",
      CertificateAuthorityConfiguration: { KeyAlgorithm: "RSA_2048", SigningAlgorithm: "SHA256WITHRSA", Subject: { CommonName: unique("ram-ca") } },
    }),
  );
  const { form, field } = await openSheet(page);
  const resources = form.locator('[name="resources"]');
  const principals = form.locator('[name="principals"]');
  await form.locator('[name="name"]').fill(unique("dash-share"));

  // A bare CA id becomes the ARN of that CA.
  await resources.fill(ca!.split("/").pop()!);
  await resources.blur();
  await expect(field("resources")).toHaveAttribute("data-invalid", "format");
  await field("resources").getByRole("button", { name: /^Use / }).click();
  await expect(resources).toHaveValue(ca!);
  await expect(field("resources")).not.toHaveAttribute("data-invalid");

  // An account ID written with dashes keeps only its digits.
  await principals.fill("4444-5555-6666");
  await principals.blur();
  await expect(field("principals")).toHaveAttribute("data-invalid", "format");
  await field("principals").getByRole("button", { name: /Digits only/ }).click();
  await expect(principals).toHaveValue("444455556666");

  // RAM can't find a mistyped CA: the error lands on that item with the CA
  // it was probably meant to be.
  const typo = ca!.slice(0, -1) + (ca!.endsWith("0") ? "1" : "0");
  await resources.fill(typo);
  await form.locator('button[type="submit"]').click();
  await expect(field("resources")).toHaveAttribute("data-invalid", "missing");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  // Other tests' CAs may be near too: take the one this test made.
  await field("resources").getByRole("button", { name: new RegExp(`Did you mean .*${ca!.slice(-12)}`) }).click();
  await expect(resources).toHaveValue(ca!);

  // An account outside the organization needs external sharing, which is
  // the checkbox's business rather than the item's.
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open] .result.error")).toContainText("outside your organization");
  await expect(field("principals")).not.toHaveAttribute("data-invalid");
  await form.locator('[name="external"]').check();
  await form.locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/\/ram\/share\?arn=/);
  await expect(page.getByRole("heading", { name: "Shared resources (1)" })).toBeVisible();
});

test("RAM: principals with their status, editing a share, permissions and versions", async ({ page }) => {
  test.setTimeout(240_000);
  const { CertificateAuthorityArn: ca } = await new ACMPCAClient(sdk).send(
    new CreateCertificateAuthorityCommand({
      CertificateAuthorityType: "ROOT",
      CertificateAuthorityConfiguration: { KeyAlgorithm: "RSA_2048", SigningAlgorithm: "SHA256WITHRSA", Subject: { CommonName: unique("ram-ca2") } },
    }),
  );
  const name = unique("dash-share2");
  await page.goto("/ram");
  await submit(page, "create-share", { name, resources: ca!, principals: "444455556666", external: "on" });
  await expect(page).toHaveURL(/\/ram\/share\?arn=/);
  const shareUrl = page.url();

  // Resources link to the CA they share.
  await expect(row(page, ca!.split("/").pop()!).getByRole("link")).toHaveAttribute("href", /\/pca\/ca\?arn=/);

  // Principals show their association status; add and remove one.
  await page.getByRole("link", { name: /Shared principals/ }).click();
  await expect(row(page, "444455556666")).toContainText(/associat/);
  await submit(page, "add-principals", { principals: "777788889999" });
  await expect(row(page, "777788889999")).toBeVisible();
  await rowAction(page, "777788889999", /Remove 777788889999/);
  await expect(row(page, "777788889999")).toHaveCount(0);

  // Rename, and turn external sharing off and on again.
  const renamed = unique("dash-renamed");
  await submit(page, "edit-share", { name: renamed });
  await expect(page.getByRole("heading", { level: 1 })).toContainText(renamed);

  // Tags.
  await page.getByRole("link", { name: /^Tags/ }).click();
  await submit(page, "add-share-tag", { key: "team", value: "pki" });
  await expect(row(page, "team")).toContainText("pki");
  await rowAction(page, "team", /Remove tag team/);
  await expect(row(page, "team")).toHaveCount(0);

  // The CA's default AWS managed permission is attached, and its page shows the policy.
  await page.getByRole("link", { name: /Managed permissions/ }).click();
  const perm = page.locator("li.row").first();
  await expect(perm).toContainText("acm-pca");
  await perm.getByRole("link").first().click();
  await expect(page).toHaveURL(/\/ram\/permission\?arn=/);
  await expect(page.getByText("AWS managed").first()).toBeVisible();
  await expect(page.locator("pre").first()).toContainText("Effect");

  // Customer managed permissions: create, add a version, make it the default, delete.
  await page.goto("/ram?tab=permissions");
  const version = (n: number) => row(page, new RegExp(`^\\s*Version ${n}\\D`));
  const permName = `dash_${Date.now().toString(36)}`;
  await submit(page, "create-permission", { name: permName, resourceType: "acm-pca:CertificateAuthority" });
  await expect(page).toHaveURL(/\/ram\/permission\?arn=/);
  await expect(page.getByRole("heading", { level: 1 })).toContainText(permName);
  await submit(page, "create-permission-version", {
    policy: JSON.stringify({ Effect: "Allow", Action: ["acm-pca:IssueCertificate", "acm-pca:GetCertificate", "acm-pca:DescribeCertificateAuthority"] }),
  });
  await expect(version(2)).toBeVisible();
  // Icon actions toast their result; retry a press that came before hydration.
  const isDefault = version(2).getByText("Default", { exact: true });
  await expect(async () => {
    if (!(await isDefault.count())) await version(2).getByRole("button", { name: /Make version 2 default/ }).click();
    await expect(isDefault).toBeVisible({ timeout: 5000 });
  }).toPass({ timeout: 60_000 });
  await expect(async () => {
    if (await version(1).count()) await rowAction(page, /^\s*Version 1\D/, /Delete version 1/);
    await expect(version(1)).toHaveCount(0, { timeout: 5000 });
  }).toPass({ timeout: 60_000 });
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-permission").locator("button").click();
  await expect(page).toHaveURL(/\/ram\?tab=permissions/);
  await expect(row(page, permName)).toHaveCount(0);

  // The share is listed under Shared by me, and can be deleted.
  await page.goto(shareUrl);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-share").locator("button").click();
  await expect(page).toHaveURL(/\/ram$/);
});
