import { expect, type Locator, type Page } from "@playwright/test";

// The tests seed what the console cannot create itself (a Lambda function
// with custom code, metric data) through the SDK, like an application would.
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

/** Fill and submit the form with `data-testid=testId`, opening its sheet
 * first when it lives in one. Resolves once the action succeeded: the sheet
 * closed, or the form shows a successful result (returned). */
export async function submit(page: Page, testId: string, fields: Record<string, string> = {}) {
  // After a client-side navigation the new page may not be there yet.
  await expect(page.getByTestId(testId).first()).toBeAttached();
  const opener = page.getByTestId(`${testId}-open`).first();
  const inSheet = (await opener.count()) > 0;
  const forms = page.getByTestId(testId).and(page.locator("form"));
  let form = forms.first();
  if (inSheet) {
    form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
    // The trigger works once React has hydrated: retry until the sheet opens.
    await expect(async () => {
      if (!(await form.isVisible())) await opener.click();
      await expect(form).toBeVisible({ timeout: 1000 });
    }).toPass();
  }
  await expect(form).toBeVisible();
  for (const [name, value] of Object.entries(fields)) {
    const field = form.locator(`[name="${name}"]`);
    const tag = await field.evaluate((e) => e.tagName);
    const type = await field.getAttribute("type");
    if (tag === "SELECT") await field.selectOption(value);
    else if (type === "checkbox") await field.setChecked(value === "on");
    else await field.fill(value);
  }
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await form.locator('button[type="submit"]').click();
  const status = form.getByRole("status");
  if (inSheet) {
    await Promise.race([form.waitFor({ state: "hidden" }), status.waitFor({ state: "visible" })]);
    if (!(await form.isVisible())) return status;
  }
  return expectOk(form);
}

/** Expect the form's result line to report success, and return it. */
export async function expectOk(form: Locator) {
  const status = form.getByRole("status");
  await expect(status).toBeVisible();
  await expect(status, (await status.textContent()) ?? "").toHaveClass(/ok/);
  return status;
}

/** The list row that mentions `text`. */
export function row(page: Page, text: string | RegExp) {
  return page.locator("li.row").filter({ hasText: text });
}

/** Press a row's icon action (by its accessible name) and accept its confirmation. */
export async function rowAction(page: Page, text: string | RegExp, button: string | RegExp) {
  page.once("dialog", (d) => d.accept().catch(() => {}));
  const r = row(page, text);
  await r.getByRole("button", { name: button }).click();
  return r;
}
