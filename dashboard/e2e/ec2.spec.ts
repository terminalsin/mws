import { DescribeImagesCommand, DescribeInstancesCommand, EC2Client, RunInstancesCommand, TerminateInstancesCommand } from "@aws-sdk/client-ec2";
import { expect, test } from "@playwright/test";
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
