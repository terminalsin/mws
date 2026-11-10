import { CreateAccountCommand, CreatePolicyCommand, DescribeCreateAccountStatusCommand, DescribePolicyCommand, ListTagsForResourceCommand, OrganizationsClient } from "@aws-sdk/client-organizations";
import { expect, test, type Page } from "@playwright/test";

import { enableOnce, ensureOrganization, row, sdk, submit, unique } from "./helpers";

test("Organizations: an OU appears in the account tree", async ({ page }) => {
  await page.goto("/organizations");
  await enableOnce(page, "create-organization", "create-ou");
  const ou = unique("Dash OU");
  await submit(page, "create-ou", { name: ou });
  await expect(page.getByLabel("Organization structure")).toContainText(ou);
});

/** Open the sheet whose form has `data-testid=testId`, and return the field
 * holding the control named `name`. */
async function openSheet(page: Page, path: string, testId: string) {
  await page.goto(path);
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, control: (name: string) => form.locator(`[name="${name}"]`) };
}

test("Organizations: account emails are checked in place", async ({ page }) => {
  await ensureOrganization();
  const orgs = new OrganizationsClient(sdk);
  const owner = `${unique("owner")}@example.com`;
  await orgs.send(new CreateAccountCommand({ AccountName: unique("Dash taken"), Email: owner }));

  // A mistyped domain gets a "did you mean".
  let { form, field, control } = await openSheet(page, "/organizations", "create-account");
  await control("email").fill("ops@gmial.com");
  await control("email").blur();
  await expect(field("email")).toHaveAttribute("data-invalid", "format");
  await field("email").getByRole("button", { name: /gmail\.com/ }).click();
  await expect(control("email")).toHaveValue("ops@gmail.com");

  // An address another account uses is flagged with a plus-addressed one.
  await control("email").fill(owner);
  await control("email").blur();
  await expect(field("email")).toHaveAttribute("data-invalid", "taken");
  await expect(field("email").getByRole("button", { name: /Use / })).toContainText(owner.replace("@", "+2@"));

  // Taken after the page loaded: AWS fails the request later, and the
  // failure still lands on the email field.
  const later = `${unique("later")}@example.com`;
  await orgs.send(new CreateAccountCommand({ AccountName: unique("Dash later"), Email: later }));
  await control("name").fill(unique("Dash account"));
  await control("email").fill(later);
  await form.locator('button[type="submit"]').click();
  await expect(field("email")).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("email").getByRole("button", { name: /Use / }).click();
  await expect(control("email")).toHaveValue(later.replace("@", "+2@"));
});

test("Organizations: SCP documents and names are repaired in place", async ({ page }) => {
  await ensureOrganization();
  const taken = unique("dash-scp");
  await new OrganizationsClient(sdk).send(
    new CreatePolicyCommand({ Name: taken, Description: "", Type: "SERVICE_CONTROL_POLICY", Content: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Action: "s3:DeleteBucket", Resource: "*" }] }) }),
  );

  const { field, control } = await openSheet(page, "/organizations?tab=policies", "create-scp");
  await control("name").fill(taken);
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(control("name")).toHaveValue(`${taken}-2`);

  // Hand-written JSON (single quotes, a trailing comma) gets fixed.
  await control("content").fill("{'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': 'ec2:*', 'Resource': '*'},]}");
  await control("content").blur();
  await expect(field("content")).toHaveAttribute("data-invalid", "format");
  await field("content").getByRole("button", { name: /Fix the JSON/ }).click();
  expect(JSON.parse(await control("content").inputValue()).Statement[0].Action).toBe("ec2:*");
  await expect(field("content")).not.toHaveAttribute("data-invalid");

  // Past the 5,120-character limit, the document is offered minified.
  const big = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Action: Array.from({ length: 160 }, (_, i) => `s3:Action${i}`), Resource: "*" }] }, null, 4);
  expect(big.length).toBeGreaterThan(5120);
  await control("content").fill(big);
  await control("content").blur();
  await expect(field("content")).toHaveAttribute("data-invalid", "tooLong");
  await field("content").getByRole("button", { name: /Minify/ }).click();
  expect((await control("content").inputValue()).length).toBeLessThanOrEqual(5120);
  await expect(field("content")).not.toHaveAttribute("data-invalid");
});

const deny = (Action: string) => JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Action, Resource: "*" }] });

test("Organizations: an SCP's content is shown, edited, attached and detached", async ({ page }) => {
  await ensureOrganization();
  const orgs = new OrganizationsClient(sdk);
  await page.goto("/organizations?tab=policies");
  const name = unique("dash-scp-edit");
  await submit(page, "create-scp", { name, content: deny("s3:DeleteBucket") });
  await row(page, name).getByRole("link").click();
  await expect(page.locator("pre[aria-label='Policy content']")).toContainText("s3:DeleteBucket");

  await submit(page, "edit-org-policy", { content: deny("ec2:TerminateInstances") });
  await expect(page.locator("pre[aria-label='Policy content']")).toContainText("ec2:TerminateInstances");
  const id = new URL(page.url()).searchParams.get("id")!;
  expect((await orgs.send(new DescribePolicyCommand({ PolicyId: id }))).Policy?.Content).toContain("ec2:TerminateInstances");

  await submit(page, "attach-policy", { target: (await page.locator("select[name=target] option:not([disabled])").first().getAttribute("value"))! });
  await expect(page.getByRole("list", { name: "Targets" }).locator("li")).toHaveCount(1);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByRole("list", { name: "Targets" }).getByRole("button", { name: /Detach from/ }).click();
  await expect(page.getByRole("list", { name: "Targets" })).toHaveCount(0);
});

test("Organizations: an account's page shows its details and takes tags", async ({ page }) => {
  await ensureOrganization();
  const orgs = new OrganizationsClient(sdk);
  const name = unique("Dash member");
  const created = await orgs.send(new CreateAccountCommand({ AccountName: name, Email: `${unique("member")}@example.com` }));
  const id = (await orgs.send(new DescribeCreateAccountStatusCommand({ CreateAccountRequestId: created.CreateAccountStatus!.Id }))).CreateAccountStatus!.AccountId!;

  await page.goto(`/organizations?account=${id}`);
  await expect(page).toHaveURL(new RegExp(`/organizations/accounts/${id}$`));
  await expect(page.locator("h1")).toHaveText(name);
  await expect(page.locator(".facts")).toContainText("created");
  await submit(page, "edit-tags", { tags: "env=dash\nteam=console" });
  await expect(page.locator(".facts")).toContainText("team");
  const tags = (await orgs.send(new ListTagsForResourceCommand({ ResourceId: id }))).Tags ?? [];
  expect(tags.map((t) => `${t.Key}=${t.Value}`).sort()).toEqual(["env=dash", "team=console"]);
});

test("Organizations: an OU is renamed in the tree", async ({ page }) => {
  await page.goto("/organizations");
  await enableOnce(page, "create-organization", "create-ou");
  const ou = unique("Dash OU");
  await submit(page, "create-ou", { name: ou });
  const tree = page.getByLabel("Organization structure");
  await expect(tree).toContainText(ou);
  const renamed = `${ou} renamed`;
  const sheet = page.getByRole("button", { name: `Rename ${ou}` });
  await sheet.click();
  const form = page.locator("dialog[open] form");
  await form.locator("[name=name]").fill(renamed);
  await form.locator('button[type="submit"]').click();
  await expect(tree).toContainText(renamed);
});
