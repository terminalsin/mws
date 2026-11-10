import { CreateEmailIdentityCommand, SESv2Client } from "@aws-sdk/client-sesv2";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("SES: verify an identity, send mail and read the outbox", async ({ page }) => {
  const from = `${unique("sender")}@example.com`;
  const subject = unique("Subject");
  await page.goto("/ses");
  await submit(page, "create-identity", { identity: from });
  await row(page, from).getByRole("button", { name: `Verify ${from}` }).click();
  await expect(row(page, from).getByRole("button", { name: `Verify ${from}` })).toHaveCount(0);

  // The account is in the SES sandbox, so it may only mail verified addresses.
  await submit(page, "send-email", { from, to: from, subject, body: "Sent from Playwright" });
  await page.goto("/ses?tab=outbox");
  await expect(page.getByText(subject)).toBeVisible();
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const input = (name: string) => form.locator(`[name="${name}"]`);
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, input, field };
}

test("SES validation: identities are cleaned up and taken ones flagged", async ({ page }) => {
  const domain = `${unique("dash")}.example.com`;
  await page.goto("/ses");
  let { form, input, field } = await openSheet(page, "create-identity");

  // A pasted URL becomes its domain.
  await input("identity").fill(`https://${domain}/welcome`);
  await input("identity").blur();
  await expect(field("identity")).toHaveAttribute("data-invalid", "format");
  await field("identity").getByRole("button", { name: /Use the domain/ }).click();
  await expect(input("identity")).toHaveValue(domain);
  await expect(field("identity")).not.toHaveAttribute("data-invalid");

  // A mistyped top-level domain is caught before AWS sees it.
  const typo = `ops@${unique("acme")}.con`;
  await input("identity").fill(typo);
  await input("identity").blur();
  await expect(field("identity")).toHaveAttribute("data-invalid", "format");
  await field("identity").getByRole("button", { name: /Did you mean \.com/ }).click();
  await expect(input("identity")).toHaveValue(typo.replace(/\.con$/, ".com"));

  // Created behind the page's back: MWS's AlreadyExists lands on the field
  // with the next free name.
  const taken = `${unique("taken")}@example.com`;
  await new SESv2Client(sdk).send(new CreateEmailIdentityCommand({ EmailIdentity: taken }));
  await input("identity").fill(taken);
  await form.locator('button[type="submit"]').click();
  await expect(field("identity")).toHaveAttribute("data-invalid", "taken");
  await expect(form.locator(".result.error")).toHaveCount(0);

  // Known when the page loads: flagged before submitting.
  await page.goto("/ses");
  ({ input, field } = await openSheet(page, "create-identity"));
  await input("identity").fill(taken);
  await input("identity").blur();
  await expect(field("identity")).toHaveAttribute("data-invalid", "taken");
});

test("SES validation: senders and sandbox recipients must be verified", async ({ page }) => {
  const sender = `${unique("verified")}@example.com`;
  await page.goto("/ses");
  await submit(page, "create-identity", { identity: sender });
  await row(page, sender).getByRole("button", { name: `Verify ${sender}` }).click();
  await expect(row(page, sender).getByRole("button", { name: `Verify ${sender}` })).toHaveCount(0);

  await page.goto("/ses");
  const { form, input, field } = await openSheet(page, "send-email");

  // An unverified sender close to a verified one: offered that one.
  await input("from").fill(sender.replace("verified", "verifed"));
  await input("from").blur();
  await expect(field("from")).toHaveAttribute("data-invalid", "pattern");
  await expect(field("from")).toContainText("Not a verified identity");
  await field("from").getByRole("button", { name: `Did you mean ${sender}?: ${sender}` }).click();
  await expect(input("from")).toHaveValue(sender);
  // A mistyped common domain.
  await input("from").fill(sender.replace("@example.com", "@exmaple.com"));
  await input("from").blur();
  await field("from").getByRole("button", { name: /Did you mean example\.com/ }).click();
  await expect(input("from")).toHaveValue(sender);
  await expect(field("from")).not.toHaveAttribute("data-invalid");

  // A pasted recipient list is tidied into one SES accepts.
  await input("to").fill(`Me <${sender}>; success@simulator.amazonses.con`);
  await input("to").blur();
  await field("to").getByRole("button", { name: /Clean up the list/ }).click();
  await expect(input("to")).toHaveValue(`${sender}, success@simulator.amazonses.com`);
  await expect(field("to")).not.toHaveAttribute("data-invalid");

  // The sandbox only mails verified addresses.
  await input("to").fill(`stranger-${Date.now()}@example.net`);
  await input("to").blur();
  await expect(field("to")).toHaveAttribute("data-invalid", "pattern");
  await expect(field("to")).toContainText("Sandbox");
  await input("to").fill(sender);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
});
