import { CreateKeyPairCommand, DeleteKeyPairCommand, DescribeImagesCommand, DescribeInstancesCommand, EC2Client, RunInstancesCommand, TerminateInstancesCommand } from "@aws-sdk/client-ec2";
import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";

import { row, submitInline, sdk, submit, unique } from "./helpers";

test("EC2: security groups flag ports open to the internet", async ({ page }) => {
  const group = unique("dash-sg");
  await page.goto("/ec2?tab=groups");
  await submit(page, "create-security-group", { name: group });
  await row(page, group).getByRole("button", { name: `Allow inbound to ${group}` }).click();
  const form = page.locator("dialog[open] form");
  await form.locator('[name="ports"]').fill("22");
  await form.locator('[name="cidr"]').fill("0.0.0.0/0");
  await form.locator('button[type="submit"]').click();
  await expect(row(page, group).locator(".chip.bad")).toContainText("22 ← anywhere");
});

/** Open the sheet behind `testId` and return its form. */
async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, input: (name: string) => form.locator(`[name="${name}"]`) };
}

test("EC2: security group and inbound rule fields repair what they reject", async ({ page }) => {
  const group = unique("dash-web");
  await page.goto("/ec2?tab=groups");
  const { form, field, input } = await openSheet(page, "create-security-group");

  // A group name can't start with sg-: the fix drops the prefix.
  await input("name").fill(`sg-${group}`);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "reserved");
  await field("name").getByRole("button", { name: /Drop sg-/ }).click();
  await expect(input("name")).toHaveValue(group);
  // "default" exists in every VPC, so it is taken whichever one is picked.
  await input("name").fill("default");
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await input("name").fill(group);
  await expect(field("name")).not.toHaveAttribute("data-invalid");
  await form.locator('button[type="submit"]').click();
  await expect(row(page, group)).toBeVisible();

  await row(page, group).getByRole("button", { name: `Allow inbound to ${group}` }).click();
  const rule = page.locator("dialog[open] form");
  const ruleField = (name: string) => rule.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  // A reversed range is swapped, a service name becomes its port.
  await rule.locator('[name="ports"]').fill("8080-8000");
  await rule.locator('[name="ports"]').blur();
  await ruleField("ports").getByRole("button", { name: /Swap the ports/ }).click();
  await expect(rule.locator('[name="ports"]')).toHaveValue("8000-8080");
  await rule.locator('[name="ports"]').fill("https");
  await rule.locator('[name="ports"]').blur();
  await ruleField("ports").getByRole("button", { name: /uses 443/ }).click();
  await expect(rule.locator('[name="ports"]')).toHaveValue("443");
  // "anywhere" stands for 0.0.0.0/0; host bits fall back to the network.
  await rule.locator('[name="cidr"]').fill("10.1.2.3/16");
  await rule.locator('[name="cidr"]').blur();
  await ruleField("cidr").getByRole("button", { name: /network address/ }).click();
  await expect(rule.locator('[name="cidr"]')).toHaveValue("10.1.0.0/16");
  await rule.locator('[name="cidr"]').fill("anywhere");
  await rule.locator('[name="cidr"]').blur();
  await ruleField("cidr").getByRole("button", { name: /Use anywhere/ }).click();
  await expect(rule.locator('[name="cidr"]')).toHaveValue("0.0.0.0/0");
  await rule.locator('button[type="submit"]').click();
  await expect(row(page, group).locator(".chip")).toContainText("443 ← anywhere");

  // The same rule again: EC2 says it is a duplicate, shown on the ports.
  await row(page, group).getByRole("button", { name: `Allow inbound to ${group}` }).click();
  await rule.locator('[name="ports"]').fill("443");
  await rule.locator('[name="cidr"]').fill("0.0.0.0/0");
  await rule.locator('button[type="submit"]').click();
  await expect(ruleField("ports")).toHaveAttribute("data-invalid", "server");
  await expect(ruleField("ports")).toContainText("already allows");
});

test("EC2: key pair names taken after the page loaded get the next free name", async ({ page }) => {
  const key = unique("dash-key");
  await page.goto("/ec2?tab=keys");
  const { form, field, input } = await openSheet(page, "create-key-pair");
  const ec2 = new EC2Client(sdk);
  await ec2.send(new CreateKeyPairCommand({ KeyName: key }));
  await input("name").fill(key);
  await form.locator('button[type="submit"]').click();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(input("name")).toHaveValue(`${key}-2`);
  await ec2.send(new DeleteKeyPairCommand({ KeyName: key }));
});

test("EC2: launch fields turn image names into IDs and catch type typos", async ({ page }) => {
  const ec2 = new EC2Client(sdk);
  const image = (await ec2.send(new DescribeImagesCommand({ Owners: ["amazon"], Filters: [{ Name: "name", Values: ["mws-alpine-*"] }] }))).Images![0];
  await page.goto("/ec2");
  const { field, input } = await openSheet(page, "launch-instance");
  await input("image").fill(image.Name!);
  await input("image").blur();
  await expect(field("image")).toHaveAttribute("data-invalid", "pattern");
  await field("image").getByRole("button", { name: `Use ${image.Name}: ${image.ImageId}` }).click();
  await expect(input("image")).toHaveValue(image.ImageId!);
  await input("type").fill("t3.mirco");
  await input("type").blur();
  await field("type").getByRole("button", { name: /Did you mean t3\.micro/ }).click();
  await expect(input("type")).toHaveValue("t3.micro");
  await expect(field("type")).not.toHaveAttribute("data-invalid");
});

const docker = (() => {
  try {
    execFileSync("docker", ["version", "--format", "{{.Server.Version}}"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

test("EC2: a terminal, files and logs on a running instance", async ({ page }) => {
  test.skip(!docker, "needs Docker to run instances");
  test.setTimeout(180_000);
  const ec2 = new EC2Client(sdk);
  const images = await ec2.send(new DescribeImagesCommand({ Owners: ["amazon"], Filters: [{ Name: "name", Values: ["mws-alpine-*"] }] }));
  const run = await ec2.send(new RunInstancesCommand({ ImageId: images.Images![0].ImageId, InstanceType: "t3.nano", MinCount: 1, MaxCount: 1 }));
  const id = run.Instances![0].InstanceId!;
  await expect(async () => {
    const d = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [id] }));
    expect(d.Reservations![0].Instances![0].State!.Name).toBe("running");
  }).toPass({ timeout: 120_000 });

  await page.goto(`/ec2/instance?id=${id}&tab=terminal`);
  const terminal = page.getByTestId("terminal");
  const command = terminal.getByLabel("Command");
  await expect(command).toBeEnabled();
  await command.fill("mkdir -p /srv/site && cd /srv/site && echo hello > index.html && ls");
  await command.press("Enter");
  await expect(terminal).toContainText("index.html");
  await expect(terminal).toContainText(":/srv/site#");

  await page.goto(`/ec2/instance?id=${id}&tab=files`);
  const files = page.getByTestId("file-explorer");
  await files.getByRole("button", { name: "/", exact: true }).click();
  await files.getByRole("button", { name: /^srv/ }).click();
  await files.getByRole("button", { name: /^site/ }).click();
  await files.getByTestId("upload").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("uploaded from the console") });
  await files.getByRole("button", { name: /^notes\.txt/ }).click();
  await expect(files.locator(".file-preview")).toContainText("uploaded from the console");

  await page.goto(`/ec2/instance?id=${id}&tab=logs`);
  await expect(page.getByLabel("Console output")).toContainText("Cloud-init");
  await ec2.send(new TerminateInstancesCommand({ InstanceIds: [id] }));
});
