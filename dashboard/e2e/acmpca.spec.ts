import { ACMPCAClient, CreateCertificateAuthorityCommand, GetCertificateAuthorityCsrCommand } from "@aws-sdk/client-acm-pca";
import { expect, test, type Page } from "@playwright/test";

import { sdk, submit, unique } from "./helpers";

// Private CA's forms validate in place: the subject's country repairs from a
// name, a CSR missing its PEM lines gets them back, and a validity past the
// CA's own expiry is clamped before MWS has to refuse it.

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => ({
    input: form.locator(`[name="${name}"]`),
    box: form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) }),
  });
  return { form, field };
}

test("Private CA: fields repair the subject, the CSR and the validity in place", async ({ page }) => {
  await page.goto("/pca");
  const { form, field } = await openSheet(page, "create-ca");

  // A common name over the model's 64 characters is shortened in one click.
  const cn = field("cn");
  await cn.input.fill(`${unique("Dash Validation Root CA")} ${"x".repeat(64)}`);
  await cn.input.blur();
  await expect(cn.box).toHaveAttribute("data-invalid", "tooLong");
  await cn.box.getByRole("button", { name: /Shorten/ }).click();
  await expect(cn.box).not.toHaveAttribute("data-invalid");
  const name = unique("Dash Validation CA");
  await cn.input.fill(name);

  // A country written out becomes its ISO code.
  const country = field("country");
  await country.input.fill("Germany");
  await country.input.blur();
  await expect(country.box).toHaveAttribute("data-invalid", "format");
  await country.box.getByRole("button", { name: /Germany: DE/ }).click();
  await expect(country.input).toHaveValue("DE");
  await expect(country.box).not.toHaveAttribute("data-invalid");
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();

  // Installing the root's certificate: a zero-year validity is raised.
  const install = await openSheet(page, "install-ca-cert");
  const years = install.field("years");
  await years.input.fill("0");
  await install.form.locator('button[type="submit"]').click();
  await expect(years.box).toHaveAttribute("data-invalid", "range");
  await years.box.getByRole("button", { name: /minimum/ }).click();
  await expect(years.input).toHaveValue("1");
  await install.form.locator('button[type="submit"]').click();
  await expect(page.locator(".specs")).toContainText("active");

  // A real CSR, pasted without its BEGIN/END lines.
  const pca = new ACMPCAClient(sdk);
  const { CertificateAuthorityArn } = await pca.send(
    new CreateCertificateAuthorityCommand({
      CertificateAuthorityType: "SUBORDINATE",
      CertificateAuthorityConfiguration: { KeyAlgorithm: "RSA_2048", SigningAlgorithm: "SHA256WITHRSA", Subject: { CommonName: unique("dash-csr") } },
    }),
  );
  let csr = "";
  await expect(async () => {
    csr = (await pca.send(new GetCertificateAuthorityCsrCommand({ CertificateAuthorityArn }))).Csr ?? "";
    expect(csr).toContain("BEGIN");
  }).toPass();
  const bare = csr.replace(/-----[A-Z ]+-----/g, "").trim();

  const issue = await openSheet(page, "issue-certificate");
  const request = issue.field("csr");
  await request.input.fill(bare);
  await request.input.blur();
  await expect(request.box).toHaveAttribute("data-invalid", "format");
  await request.box.getByRole("button", { name: /BEGIN\/END/ }).click();
  await expect(request.input).toHaveValue(/^-----BEGIN CERTIFICATE REQUEST-----\n/);
  await expect(request.box).not.toHaveAttribute("data-invalid");

  // The CA lives one year, so ten years are lowered to what it has left.
  const days = issue.field("days");
  await days.input.fill("3650");
  await days.input.blur();
  await expect(days.box).toHaveAttribute("data-invalid", "range");
  await days.box.getByRole("button", { name: /maximum/ }).click();
  await expect(days.box).not.toHaveAttribute("data-invalid");
  expect(Number(await days.input.inputValue())).toBeLessThanOrEqual(366);
  await issue.form.locator('button[type="submit"]').click();
  await expect(issue.form.getByRole("status")).toContainText("Issued");
});

test("Private CA: a pasted private key is refused before it is sent", async ({ page }) => {
  const cn = unique("Dash Key Guard CA");
  await page.goto("/pca");
  await submit(page, "create-ca", { cn });
  await submit(page, "install-ca-cert");
  const { form, field } = await openSheet(page, "issue-certificate");
  const request = field("csr");
  await request.input.fill("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----");
  await form.locator('button[type="submit"]').click();
  await expect(request.box).toHaveAttribute("data-invalid", "format");
  await expect(request.box).toContainText("private key");
  await expect(request.input).toBeFocused();
});
