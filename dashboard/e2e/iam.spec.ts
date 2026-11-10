import { CreateGroupCommand, CreatePolicyCommand, CreateUserCommand, IAMClient } from "@aws-sdk/client-iam";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("IAM: create a role, attach a managed policy, group roles by who trusts them", async ({ page }) => {
  const role = unique("dash-role");
  await page.goto("/iam?tab=roles");
  await submit(page, "create-role", { name: role });
  await page.getByRole("link", { name: role }).click();
  await expect(page.locator("pre[aria-label='Trust policy']")).toContainText("lambda.amazonaws.com");
  await submit(page, "attach-policy", { policyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" });
  await expect(row(page, "ReadOnlyAccess")).toBeVisible();

  await page.goto("/iam?tab=roles");
  await expect(row(page, role)).toContainText("lambda.amazonaws.com");
});

test("IAM: a user gets an access key, shown once", async ({ page }) => {
  const user = unique("dash-user");
  await page.goto("/iam");
  await submit(page, "create-user", { name: user });
  await page.getByRole("link", { name: user }).click();
  const result = await submit(page, "create-access-key");
  await expect(result).toContainText("AWS_SECRET_ACCESS_KEY=");
});

// Inline validation (packages/ui validation.ts) on IAM's forms.

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, control: (name: string) => form.locator(`[name="${name}"]`) };
}

test("IAM validation: names, paths and service principals are repaired in place", async ({ page }) => {
  const user = unique("Dash User");
  await page.goto("/iam");
  const { form, field, control } = await openSheet(page, "create-user");
  await control("name").fill(user);
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /Replace spaces/ }).click();
  await expect(control("name")).toHaveValue(user.replace(/\s+/g, "-"));

  await control("path").fill("team");
  await control("path").blur();
  await expect(field("path")).toHaveAttribute("data-invalid", "format");
  await field("path").getByRole("button", { name: /Fix the path/ }).click();
  await expect(control("path")).toHaveValue("/team/");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByRole("link", { name: user.replace(/\s+/g, "-") })).toBeVisible();

  // A role: "lambda" becomes a service principal, and a bare, lowercase
  // trust statement becomes a policy document.
  const role = unique("dash-role");
  await page.goto("/iam?tab=roles");
  const r = await openSheet(page, "create-role");
  await r.control("name").fill(role);
  await r.control("service").fill("lambda");
  await r.control("service").blur();
  await expect(r.field("service")).toHaveAttribute("data-invalid", "pattern");
  await r.field("service").getByRole("button", { name: /amazonaws\.com/ }).click();
  await expect(r.control("service")).toHaveValue("lambda.amazonaws.com");
  await r.control("trust").fill(`{effect: 'allow', principal: {"Service": "ecs-tasks.amazonaws.com"}, action: 'sts:AssumeRole'}`);
  await r.control("trust").blur();
  await expect(r.field("trust")).toHaveAttribute("data-invalid", "format");
  await r.field("trust").getByRole("button", { name: /Fix the policy/ }).click();
  await expect(r.field("trust")).not.toHaveAttribute("data-invalid");
  await r.form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, role)).toContainText("ecs-tasks.amazonaws.com");
});

test("IAM validation: taken names, unknown policies and rejected documents land on their field", async ({ page }) => {
  const client = new IAMClient(sdk);
  const group = unique("dash-group");
  const user = unique("dash-member");
  const policy = unique("dash-policy");
  await client.send(new CreateGroupCommand({ GroupName: group }));
  await client.send(new CreateUserCommand({ UserName: user }));
  await client.send(
    new CreatePolicyCommand({
      PolicyName: policy,
      PolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:ListBucket", Resource: "*" }] }),
    }),
  );

  // A group that exists: flagged before submitting, with the next free name.
  await page.goto("/iam?tab=groups");
  const g = await openSheet(page, "create-group");
  await g.control("name").fill(group);
  await g.control("name").blur();
  await expect(g.field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(g.field("name").getByRole("button", { name: /Use / })).toContainText(`${group}-2`);

  // A bare policy name: not an ARN, but close to one the user can attach.
  await page.goto(`/iam/users/${encodeURIComponent(user)}`);
  const a = await openSheet(page, "attach-policy");
  await a.control("policyArn").fill(policy);
  await a.control("policyArn").blur();
  await expect(a.field("policyArn")).toHaveAttribute("data-invalid", "format");
  await a.field("policyArn").getByRole("button", { name: /Did you mean/ }).click();
  await expect(a.control("policyArn")).toHaveValue(new RegExp(`^arn:aws:iam::\\d{12}:policy/${policy}$`));
  await a.form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, policy)).toBeVisible();

  // An ARN that looks right but does not exist: MWS answers NoSuchEntity,
  // which shows on the field rather than under the form.
  const b = await openSheet(page, "attach-policy");
  await b.control("policyArn").fill("arn:aws:iam::aws:policy/NoSuchPolicyAnywhere");
  await b.form.locator('button[type="submit"]').click();
  await expect(b.field("policyArn")).toHaveAttribute("data-invalid", "missing");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
});
