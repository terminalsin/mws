import { expect, type Locator, type Page } from "@playwright/test";

// The tests seed what the console cannot create itself (a Lambda function
// needs a deployment package) through the SDK, like an application would.
export const sdk = {
  endpoint: process.env.MWS_ENDPOINT ?? "http://127.0.0.1:4566",
  region: process.env.MWS_REGION ?? "us-east-1",
  credentials: {
    accessKeyId: process.env.MWS_ACCESS_KEY_ID ?? "AKIAMWSROOTEXAMPLE00",
    secretAccessKey: process.env.MWS_SECRET_ACCESS_KEY ?? "mwsRootSecretAccessKeyEXAMPLEKEY00000000",
  },
};

/** A name nobody else uses, so tests can share one MWS without resetting it. */
export function unique(prefix: string) {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

/** Submit the form with `data-testid=testId` and wait for its outcome. */
export async function submit(page: Page, testId: string, fields: Record<string, string> = {}) {
  const form = page.getByTestId(testId);
  for (const [name, value] of Object.entries(fields)) {
    const field = form.locator(`[name="${name}"]`);
    const tag = await field.evaluate((e) => e.tagName);
    if (tag === "SELECT") await field.selectOption(value);
    else await field.fill(value);
  }
  await form.locator('button[type="submit"]').click();
  return expectOk(form);
}

/** Expect the form's result line to report success, and return it. */
export async function expectOk(form: Locator) {
  const status = form.getByRole("status");
  await expect(status).toBeVisible();
  await expect(status, (await status.textContent()) ?? "").toHaveClass(/ok/);
  return status;
}

/** Click a row's inline action button and accept its confirmation, if any. */
export async function rowAction(page: Page, rowText: string | RegExp, button: string) {
  page.once("dialog", (d) => d.accept());
  const row = page.getByRole("row").filter({ hasText: rowText });
  await row.getByRole("button", { name: button }).click();
  return row;
}
