import { CreateOrganizationCommand, OrganizationsClient } from "@aws-sdk/client-organizations";
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
    await reveal(field);
    const tag = await field.evaluate((e) => e.tagName);
    const type = await field.getAttribute("type");
    if (tag === "SELECT") await field.selectOption(value);
    else if (type === "checkbox") await field.setChecked(value === "on");
    else await field.fill(value);
  }
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await lastStep(form);
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

/** Turn a service on if this MWS has not yet: the page then becomes the
 * service's own, so wait for one of its controls instead of a result. */
export async function enableOnce(page: Page, enable: string, next: string) {
  await expect(page.getByTestId(enable).or(page.getByTestId(next)).first()).toBeAttached();
  if ((await page.getByTestId(enable).count()) > 0) {
    await expect(async () => {
      if ((await page.getByTestId(enable).count()) > 0) await page.getByTestId(enable).locator('button[type="submit"]').click();
      await expect(page.getByTestId(next).first()).toBeAttached({ timeout: 3000 });
    }).toPass();
  }
}

/** Fill a form that is on the page (not in a sheet) and return its result line. */
export async function submitInline(page: Page, testId: string, fields: Record<string, string>) {
  const form = page.getByTestId(testId).and(page.locator("form"));
  for (const [name, value] of Object.entries(fields)) await form.locator(`[name="${name}"]`).fill(value);
  await form.locator('button[type="submit"]').click();
  const status = form.getByRole("status");
  await expect(status).toBeVisible();
  return status;
}

/** Make this MWS account an organization's management account, unless it
 * already is (Identity Center permission sets and SCPs need one). Specs run in
 * parallel, so whichever gets here first creates it. */
export async function ensureOrganization() {
  try {
    await new OrganizationsClient(sdk).send(new CreateOrganizationCommand({ FeatureSet: "ALL" }));
  } catch (e) {
    if ((e as { name?: string }).name !== "AlreadyInOrganizationException") throw e;
  }
}

/** Wait until `status()` returns `want`, moving MWS's emulated clock on
 * while waiting (EKS clusters, node groups and other slow resources take
 * minutes on it, as on AWS), then put the clock back. Resources stay settled
 * once a read has seen them settle, so other specs sharing MWS are not
 * affected. */
export async function settleWithClock(status: () => Promise<string | undefined>, want: string, stepSeconds = 30) {
  const clock = async (body?: object) =>
    (await (await fetch(`${sdk.endpoint}/_mws/clock`, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {})).json()) as { offsetSeconds: number };
  const before = (await clock()).offsetSeconds;
  try {
    await expect
      .poll(async () => {
        const now = await status();
        if (now !== want) await clock({ advanceSeconds: stepSeconds });
        return now;
      }, { timeout: 60_000 })
      .toBe(want);
  } finally {
    await clock({ offsetSeconds: before });
  }
}

/** Open the form section (step or tab) that holds `control`, when the form
 * is split into sections and it is in another one. */
export async function reveal(control: Locator) {
  await control.first().evaluate((el) => {
    const panel = el.closest(".section-panel");
    if (!panel || !(panel as HTMLElement).hidden) return;
    const root = panel.parentElement!;
    const i = [...root.querySelectorAll(":scope > .section-panel")].indexOf(panel);
    (root.querySelectorAll(':scope > [role="tablist"] > [role="tab"]')[i] as HTMLElement | undefined)?.click();
  });
}

/** Move a stepped form to its last step, where the submit button is. */
export async function lastStep(form: Locator) {
  await form.evaluate((el) => {
    for (const root of el.querySelectorAll('.form-sections[data-last="false"]')) {
      const tabs = root.querySelectorAll(':scope > [role="tablist"] > [role="tab"]');
      (tabs[tabs.length - 1] as HTMLElement | undefined)?.click();
    }
  });
}
