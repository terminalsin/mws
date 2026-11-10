import {
  AddUserToGroupCommand,
  AttachUserPolicyCommand,
  CreateAccessKeyCommand,
  CreateGroupCommand,
  CreateLoginProfileCommand,
  CreatePolicyCommand,
  CreateUserCommand,
  GetUserCommand,
  IAMClient,
  ListPolicyVersionsCommand,
  PutUserPolicyCommand,
} from "@aws-sdk/client-iam";
import { expect, test, type Page } from "@playwright/test";

import { row, rowAction, sdk, submit, unique } from "./helpers";

test("IAM: create a role, attach a managed policy, group roles by who trusts them", async ({ page }) => {
  const role = unique("dash-role");
  await page.goto("/iam?tab=roles");
  await submit(page, "create-role", { name: role });
  await page.getByRole("link", { name: role }).click();
  await submit(page, "attach-policy", { policyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" });
  await expect(row(page, "ReadOnlyAccess")).toBeVisible();
  await page.getByRole("link", { name: "Trust relationships" }).click();
  await expect(page.locator("pre[aria-label='Trust policy']")).toContainText("lambda.amazonaws.com");

  await page.goto("/iam?tab=roles");
  await expect(row(page, role)).toContainText("lambda.amazonaws.com");
});

test("IAM: a user gets an access key, shown once", async ({ page }) => {
  const user = unique("dash-user");
  await page.goto("/iam");
  await submit(page, "create-user", { name: user });
  await page.getByRole("link", { name: user }).click();
  await page.getByRole("link", { name: "Security credentials" }).click();
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
  await a.field("policyArn").getByRole("button", { name: new RegExp(`Did you mean|Use ${policy}`) }).first().click();
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

const doc = (Action: string) => JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action, Resource: "*" }] });

test("IAM: editing a managed policy saves versions, which can be made default and deleted", async ({ page }) => {
  const client = new IAMClient(sdk);
  const name = unique("dash-versions");
  const arn = (await client.send(new CreatePolicyCommand({ PolicyName: name, PolicyDocument: doc("s3:ListBucket") }))).Policy!.Arn!;
  await page.goto(`/iam/policy?arn=${encodeURIComponent(arn)}`);
  await expect(page.locator("pre[aria-label='Policy document']")).toContainText("s3:ListBucket");
  await submit(page, "edit-policy", { document: doc("sqs:SendMessage") });
  await expect(page.locator("pre[aria-label='Policy document']")).toContainText("sqs:SendMessage");

  await page.getByRole("link", { name: /Policy versions/ }).click();
  await expect(row(page, "v2")).toContainText("Default version");
  await row(page, "v1").getByRole("button", { name: "Set v1 as default" }).click();
  await expect(row(page, "v1")).toContainText("Default version");
  await rowAction(page, "v2", "Delete v2");
  await expect(row(page, "v2")).toHaveCount(0);
  const versions = (await client.send(new ListPolicyVersionsCommand({ PolicyArn: arn }))).Versions!;
  expect(versions.map((v) => v.VersionId)).toEqual(["v1"]);
});

test("IAM: a group's inline policy is created, read and edited", async ({ page }) => {
  const group = unique("dash-inline");
  await new IAMClient(sdk).send(new CreateGroupCommand({ GroupName: group }));
  await page.goto(`/iam/groups/${group}?tab=permissions`);
  await submit(page, "inline-policy", { policyName: "ReadQueues", document: doc("sqs:ReceiveMessage") });
  await row(page, "ReadQueues").getByRole("link").click();
  await expect(page.locator("pre[aria-label='Policy document']")).toContainText("sqs:ReceiveMessage");
  await submit(page, "edit-inline-policy", { document: doc("sqs:DeleteMessage") });
  await expect(page.locator("pre[aria-label='Policy document']")).toContainText("sqs:DeleteMessage");
});

test("IAM: a group's members are added and removed from the group", async ({ page }) => {
  const client = new IAMClient(sdk);
  const group = unique("dash-members");
  const user = unique("dash-joiner");
  await client.send(new CreateGroupCommand({ GroupName: group }));
  await client.send(new CreateUserCommand({ UserName: user }));
  await page.goto(`/iam/groups/${group}`);
  await submit(page, "add-member", { user });
  await expect(row(page, user)).toBeVisible();
  await row(page, user).getByRole("button", { name: `Remove ${user}` }).click();
  await expect(row(page, user)).toHaveCount(0);
});

test("IAM: deleting a user removes its keys, password, groups and policies first", async ({ page }) => {
  const client = new IAMClient(sdk);
  const user = unique("dash-busy");
  const group = unique("dash-busy-group");
  await client.send(new CreateUserCommand({ UserName: user }));
  await client.send(new CreateGroupCommand({ GroupName: group }));
  await client.send(new AddUserToGroupCommand({ UserName: user, GroupName: group }));
  await client.send(new CreateAccessKeyCommand({ UserName: user }));
  await client.send(new CreateLoginProfileCommand({ UserName: user, Password: "Dash-board-1234!" }));
  await client.send(new AttachUserPolicyCommand({ UserName: user, PolicyArn: "arn:aws:iam::aws:policy/ReadOnlyAccess" }));
  await client.send(new PutUserPolicyCommand({ UserName: user, PolicyName: "inline", PolicyDocument: doc("s3:ListBucket") }));

  await page.goto(`/iam/users/${user}`);
  await expect(page.getByText("enabled").first()).toBeVisible();
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-user").locator("button").click();
  await expect(page).toHaveURL(/\/iam$/);
  await expect(client.send(new GetUserCommand({ UserName: user }))).rejects.toMatchObject({ name: "NoSuchEntityException" });
});

test("IAM: the policy simulator tells which actions a user may take", async ({ page }) => {
  const client = new IAMClient(sdk);
  const user = unique("dash-sim");
  await client.send(new CreateUserCommand({ UserName: user }));
  await client.send(new PutUserPolicyCommand({ UserName: user, PolicyName: "queues", PolicyDocument: doc("sqs:SendMessage") }));
  const arn = (await client.send(new GetUserCommand({ UserName: user }))).User!.Arn!;
  await page.goto(`/iam/simulator?principal=${encodeURIComponent(arn)}&actions=${encodeURIComponent("sqs:SendMessage, s3:GetObject")}`);
  const results = page.getByRole("table", { name: "Simulation results" });
  await expect(results.locator("tr").filter({ hasText: "sqs:SendMessage" })).toContainText("allowed");
  await expect(results.locator("tr").filter({ hasText: "s3:GetObject" })).toContainText("not allowed");
});
