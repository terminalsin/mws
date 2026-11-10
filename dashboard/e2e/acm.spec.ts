import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, test, type Page } from "@playwright/test";

import { submit, unique } from "./helpers";

test("Certificates: a private CA issues a certificate requested through ACM", async ({ page }) => {
  const cn = unique("Dash Root CA");
  await page.goto("/pca");
  await submit(page, "create-ca", { cn });
  await expect(page.getByRole("heading", { level: 1, name: cn })).toBeVisible();
  await submit(page, "install-ca-cert");
  await expect(page.locator(".specs")).toContainText("active");

  const domain = `${unique("svc")}.internal.example`;
  await page.goto("/acm");
  await submit(page, "request-certificate", { domains: domain, pca: `Private · ${cn}` });
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  await expect(page.locator(".specs")).toContainText(/Issued|Pending/);
});

// Inline validation (packages/ui validation.ts): the forms repair what
// people usually paste, and ImportCertificate's errors land on their field.

async function openSheet(page: Page, testId: string) {
  await page.goto("/acm");
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field };
}

function selfSigned(cn: string) {
  const dir = mkdtempSync(join(tmpdir(), "acm-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30", "-subj", `/CN=${cn}`, "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });
  return { cert: readFileSync(join(dir, "cert.pem"), "utf8"), key: readFileSync(join(dir, "key.pem"), "utf8") };
}

test("Certificates: domain names are cleaned up in place", async ({ page }) => {
  const { form, field } = await openSheet(page, "request-certificate");
  const domains = form.locator('textarea[name="domains"]');
  const name = `${unique("shop")}.example.com`;
  await domains.fill(`${name}\nhttps://www.${name}/login`);
  await domains.blur();
  await expect(field("domains")).toHaveAttribute("data-invalid", "format");
  await expect(field("domains").locator(".field-issue")).toContainText("Just the domain name");
  await field("domains").getByRole("button", { name: /Clean up/ }).click();
  await expect(domains).toHaveValue(`${name}\nwww.${name}`);
  await expect(field("domains")).not.toHaveAttribute("data-invalid");

  await domains.fill(`*${name.replace(/\.com$/, ".con")}`);
  await domains.blur();
  await field("domains").getByRole("button", { name: /Did you mean/ }).click();
  await expect(domains).toHaveValue(`*.${name}`);
});

test("Certificates: imports catch swapped and escaped PEM, and land MWS errors on the field", async ({ page }) => {
  const a = selfSigned(`${unique("a")}.example.com`);
  const b = selfSigned(`${unique("b")}.example.com`);
  const { form, field } = await openSheet(page, "import-certificate");
  const cert = form.locator('textarea[name="certificate"]');
  const key = form.locator('textarea[name="key"]');

  // The key pasted where the certificate goes.
  await cert.fill(a.key);
  await cert.blur();
  await expect(field("certificate").locator(".field-issue")).toContainText("private key, not a certificate");

  // A PEM copied out of JSON keeps its line breaks escaped.
  await cert.fill(a.cert.trim().replace(/\n/g, "\\n"));
  await cert.blur();
  await field("certificate").getByRole("button", { name: /Restore the line breaks/ }).click();
  await expect(field("certificate")).not.toHaveAttribute("data-invalid");

  // Another certificate's key: only MWS can tell, and it says so on the key.
  await key.fill(b.key);
  await form.locator('button[type="submit"]').click();
  await expect(field("key")).toHaveAttribute("data-invalid", "server");
  await expect(field("key").locator(".field-issue")).toContainText("Doesn't belong to this certificate");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);

  await key.fill(a.key);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator(".specs")).toContainText("Imported");
});
