import { ACMPCAClient, CreateCertificateAuthorityCommand } from "@aws-sdk/client-acm-pca";
import { expect, test, type Page } from "@playwright/test";

import { sdk, unique } from "./helpers";

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
  await field("resources").getByRole("button", { name: /Did you mean/ }).click();
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
