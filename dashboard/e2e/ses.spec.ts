import { CreateHostedZoneCommand, Route53Client } from "@aws-sdk/client-route-53";
import { DescribeActiveReceiptRuleSetCommand, SESClient, SetActiveReceiptRuleSetCommand } from "@aws-sdk/client-ses";
import { CreateEmailIdentityCommand, SESv2Client } from "@aws-sdk/client-sesv2";
import { CreateTopicCommand, SNSClient } from "@aws-sdk/client-sns";
import { expect, test, type Page } from "@playwright/test";

import { row, rowAction, sdk, submit, unique } from "./helpers";

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

test("SES: a domain identity's DNS records, published to Route 53, verify it", async ({ page }) => {
  test.setTimeout(180_000);
  const domain = `${unique("mail")}.example.com`;
  await new Route53Client(sdk).send(new CreateHostedZoneCommand({ Name: domain, CallerReference: unique("ses-zone") }));
  await page.goto("/ses");
  await submit(page, "create-identity", { identity: domain });
  await expect(page).toHaveURL(/\/ses\/identity\?name=/);
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  const records = page.getByRole("table", { name: "DNS records" });
  // SES v2 verifies domains with Easy DKIM: three CNAMEs.
  await expect(records.getByText(/\._domainkey\./)).toHaveCount(3);
  await expect(page.getByText("pending").first()).toBeVisible();

  // A custom MAIL FROM domain adds its MX and SPF records.
  await page.getByRole("link", { name: "Authentication" }).click();
  await submit(page, "mail-from", { mailFrom: `bounce.${domain}` });
  await expect(page.getByText(`bounce.${domain}`).first()).toBeVisible();
  await page.getByRole("link", { name: "DNS records" }).click();
  await expect(records).toContainText("feedback-smtp.");

  // Publishing them to the zone is how SES verifies the domain.
  await page.getByTestId("publish-records").locator("button").click();
  await expect(page.getByText(/Published \d+ records/).first()).toBeAttached();
  await expect(async () => {
    await page.reload();
    await expect(page.getByText("verified", { exact: true }).first()).toBeVisible({ timeout: 3000 });
  }).toPass({ timeout: 60_000 });
  await page.goto(`/route53`);
  await row(page, domain).getByRole("link").first().click();
  await expect(row(page, `._domainkey.${domain}`).first()).toBeVisible();

  // Notifications and feedback forwarding.
  await page.goto(`/ses/identity?name=${encodeURIComponent(domain)}&tab=notifications`);
  await page.getByTestId("feedback-forwarding").locator("button").click();
  await expect(row(page, "Email feedback forwarding")).toContainText("on");
});

test("SES: configuration sets with event destinations, templates and a templated send", async ({ page }) => {
  test.setTimeout(240_000);
  const sender = `${unique("cfg")}@example.com`;
  const ses2 = new SESv2Client(sdk);
  await ses2.send(new CreateEmailIdentityCommand({ EmailIdentity: sender }));
  await fetch(`${sdk.endpoint}/_aws/ses/verify-identity?${new URLSearchParams({ identity: sender, region: sdk.region })}`, { method: "POST" });
  const { TopicArn } = await new SNSClient(sdk).send(new CreateTopicCommand({ Name: unique("ses-events") }));

  // A configuration set with an SNS destination.
  const set = unique("dash-set");
  await page.goto("/ses?tab=configsets");
  await submit(page, "create-config-set", { name: set });
  await expect(page).toHaveURL(/\/ses\/configset\?name=/);
  await submit(page, "add-destination", { destName: "to-sns", topic: TopicArn! });
  await expect(row(page, "to-sns")).toContainText("enabled");
  await expect(row(page, "to-sns")).toContainText("delivery");
  await submit(page, "edit-config-set", { reputation: "on", tls: "REQUIRE" });
  await expect(page.getByText("Required")).toBeVisible();

  // A template, rendered with sample data.
  const template = unique("dash-tpl");
  await page.goto("/ses?tab=templates");
  await submit(page, "create-template", { name: template, subject: "Hello {{name}}", text: "Order {{order}} shipped" });
  await expect(page).toHaveURL(/\/ses\/template\?name=/);
  await expect(page.getByText("{{name}}, {{order}}")).toBeVisible();
  await submit(page, "test-render", { data: '{"name":"Ana","order":"42"}' });
  await expect(page.locator("dialog[open] pre")).toContainText("Subject: Hello Ana");
  await page.keyboard.press("Escape");

  // A templated send through the configuration set.
  await page.goto("/ses");
  await submit(page, "send-email", { from: sender, to: sender, template, templateData: '{"name":"Ana","order":"42"}', configSet: set });
  await page.goto("/ses?tab=outbox");
  const mail = row(page, "Hello Ana").first();
  await expect(mail).toContainText(template);
  await expect(mail).toContainText(set);

  // Cleanup through the console.
  await page.goto(`/ses/configset?name=${encodeURIComponent(set)}`);
  await rowAction(page, "to-sns", /Delete to-sns/);
  await expect(row(page, "to-sns")).toHaveCount(0);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-config-set").locator("button").click();
  await expect(page).toHaveURL(/\/ses\?tab=configsets/);
});

test("SES: receipt rule sets, rules and received mail", async ({ page }) => {
  test.setTimeout(240_000);
  const domain = `${unique("inbound")}.example.com`;
  const ses2 = new SESv2Client(sdk);
  const ses1 = new SESClient(sdk);
  await ses2.send(new CreateEmailIdentityCommand({ EmailIdentity: domain }));
  await fetch(`${sdk.endpoint}/_aws/ses/verify-identity?${new URLSearchParams({ identity: domain, region: sdk.region })}`, { method: "POST" });
  // The active rule set is account-wide: put back whichever was active.
  const before = (await ses1.send(new DescribeActiveReceiptRuleSetCommand({}))).Metadata?.Name;
  const name = unique("dash-rules");
  try {
    await page.goto("/ses?tab=receiving");
    await submit(page, "create-rule-set", { name, activate: "on" });
    await expect(page).toHaveURL(/\/ses\/ruleset\?name=/);
    await expect(page.getByText("active").first()).toBeVisible();

    // Two rules; the second moves first.
    await submit(page, "create-rule", { ruleName: "tag-it", recipients: domain, "do:header": "on" });
    await expect(row(page, "tag-it")).toContainText("Header X-Received-By");
    await submit(page, "create-rule", { ruleName: "stop-here", recipients: `support@${domain}`, "do:stop": "on" });
    await expect(row(page, "2. stop-here")).toBeVisible();
    await rowAction(page, "stop-here", /Move stop-here up/);
    await expect(row(page, "1. stop-here")).toBeVisible();

    // Mail for the domain runs the rules, and the console shows what they did.
    await page.goto("/ses?tab=receiving");
    const subject = unique("Inbound");
    await submit(page, "receive-test", { to: `sales@${domain}`, subject });
    await page.reload();
    const received = row(page, subject);
    await expect(received).toContainText("tag-it");
    await expect(received).not.toContainText("stop-here");

    // IP filters.
    const filter = unique("block");
    await submit(page, "create-filter", { filterName: filter, cidr: "203.0.113.0/24" });
    await expect(row(page, filter)).toContainText("Block");
    await rowAction(page, filter, new RegExp(`Delete ${filter}`));
    await expect(row(page, filter)).toHaveCount(0);

    // Edit a rule, then delete the set (deactivated first, as SES requires).
    await page.goto(`/ses/ruleset?name=${encodeURIComponent(name)}`);
    await submit(page, "edit-rule-tag-it", { enabled: "off" });
    await expect(row(page, "tag-it")).toContainText("disabled");
    await page.getByTestId("deactivate-rule-set").locator("button").click();
    await expect(page.getByTestId("activate-rule-set")).toBeVisible();
    page.once("dialog", (d) => d.accept().catch(() => {}));
    await page.getByTestId("delete-rule-set").locator("button").click();
    await expect(page).toHaveURL(/\/ses\?tab=receiving/);
  } finally {
    if (before) await ses1.send(new SetActiveReceiptRuleSetCommand({ RuleSetName: before })).catch(() => {});
  }
});

test("SES: the suppression list", async ({ page }) => {
  const email = `${unique("bounced")}@example.com`;
  await page.goto("/ses?tab=suppression");
  await submit(page, "suppress", { email, reason: "COMPLAINT" });
  await expect(row(page, email)).toContainText("complaint");
  await rowAction(page, email, new RegExp(`Remove ${email}`));
  await expect(row(page, email)).toHaveCount(0);
});
