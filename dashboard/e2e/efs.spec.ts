import { expect, test, type Page } from "@playwright/test";

import { CreateSecurityGroupCommand, DescribeSubnetsCommand, DescribeVpcsCommand, EC2Client } from "@aws-sdk/client-ec2";
import { DescribeMountTargetsCommand, DescribeMountTargetSecurityGroupsCommand, EFSClient } from "@aws-sdk/client-efs";

import { row, sdk, submit, unique } from "./helpers";

test("EFS: a file system with an access point", async ({ page }) => {
  const name = unique("dash-fs");
  await page.goto("/efs");
  await submit(page, "create-file-system", { name, vpc: "" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await page.getByRole("link", { name: "Access points" }).click();
  await submit(page, "create-access-point", { name: "app", path: "/app" });
  await expect(row(page, "/app")).toBeVisible();
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => ({
    input: form.locator(`[name="${name}"]`),
    box: form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) }),
  });
  return { form, field };
}

test("EFS: fields repair names, root directories and user ids in place", async ({ page }) => {
  await page.goto("/efs");
  let { form, field } = await openSheet(page, "create-file-system");

  // The Name tag rejects "!": offered without it.
  const name = field("name");
  const fs = unique("dash-fs-check");
  await name.input.fill(`${fs}!`);
  await name.input.blur();
  await expect(name.box).toHaveAttribute("data-invalid", "pattern");
  await name.box.getByRole("button", { name: /Remove unsupported/ }).click();
  await expect(name.input).toHaveValue(fs);
  await expect(name.box).not.toHaveAttribute("data-invalid");
  await form.locator('select[name="vpc"]').selectOption("");
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: fs })).toBeVisible();
  await page.getByRole("link", { name: "Access points" }).click();

  ({ form, field } = await openSheet(page, "create-access-point"));
  const path = field("path");
  // A relative path with a doubled slash, a space and a trailing slash
  // becomes one absolute, clean path.
  await path.input.fill("srv//my data/");
  await path.input.blur();
  await expect(path.box).toHaveAttribute("data-invalid", "format");
  await path.box.getByRole("button", { name: /Clean up the path/ }).click();
  await expect(path.input).toHaveValue("/srv/my-data");
  await expect(path.box).not.toHaveAttribute("data-invalid");

  // EFS allows four levels: the fix keeps the first four.
  await path.input.fill("/a/b/c/d/e");
  await path.input.blur();
  await expect(path.box).toHaveAttribute("data-invalid", "pattern");
  await path.box.getByRole("button", { name: /Keep 4 levels/ }).click();
  await expect(path.input).toHaveValue("/a/b/c/d");

  // A user id past the 32-bit range is clamped to the largest one.
  const uid = field("uid");
  await uid.input.fill("5000000000");
  await uid.input.blur();
  await expect(uid.box).toHaveAttribute("data-invalid", "range");
  await uid.box.getByRole("button", { name: /Lower to the maximum/ }).click();
  await expect(uid.input).toHaveValue("4294967295");

  await form.locator('button[type="submit"]').click();
  await expect(row(page, "/a/b/c/d")).toBeVisible();
});

test("EFS: mount targets, their security groups, the file system policy and lifecycle", async ({ page }) => {
  const name = unique("dash-fs-net");
  const ec2 = new EC2Client(sdk);
  const vpc = (await ec2.send(new DescribeVpcsCommand({ Filters: [{ Name: "is-default", Values: ["true"] }] }))).Vpcs![0].VpcId!;
  const subnets = (await ec2.send(new DescribeSubnetsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc] }] }))).Subnets!;
  const sgName = unique("dash-nfs");
  const sg = (await ec2.send(new CreateSecurityGroupCommand({ GroupName: sgName, Description: "NFS", VpcId: vpc }))).GroupId!;

  await page.goto("/efs");
  // The lifecycle policy waits under More.
  const sheet = await openSheet(page, "create-file-system");
  await sheet.form.locator(".more-fields > summary").click();
  await submit(page, "create-file-system", { name, vpc, ia: "AFTER_14_DAYS" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const id = new URL(page.url()).searchParams.get("id")!;
  await expect(page.getByRole("definition").filter({ hasText: "14 days after last access" })).toBeVisible();

  // Network: one mount target per zone, linked to its subnet; swap its security groups.
  await page.getByRole("link", { name: /^Network/ }).click();
  const zones = new Set(subnets.map((s) => s.AvailabilityZone));
  await expect(page.locator('ul[aria-label="Mount targets"] li.row')).toHaveCount(zones.size);
  const efs = new EFSClient(sdk);
  const target = (await efs.send(new DescribeMountTargetsCommand({ FileSystemId: id }))).MountTargets![0];
  await expect(page.getByRole("link", { name: target.SubnetId! })).toHaveAttribute("href", `/vpc/subnet?id=${target.SubnetId}`);
  await page.getByTestId(`edit-sgs-${target.AvailabilityZoneName}-open`).click();
  const form = page.locator("dialog[open]").getByTestId(`edit-sgs-${target.AvailabilityZoneName}`).and(page.locator("form"));
  await form.locator('input[name="groups"]').evaluateAll((els) => els.forEach((e) => ((e as HTMLInputElement).checked = false)));
  await form.locator(`input[name="groups"][value="${sg}"]`).check();
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, target.SubnetId!)).toContainText(sgName);
  expect((await efs.send(new DescribeMountTargetSecurityGroupsCommand({ MountTargetId: target.MountTargetId }))).SecurityGroups).toEqual([sg]);

  // Delete one mount target, then add it back.
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await row(page, target.SubnetId!).getByRole("button", { name: `Delete mount target ${target.AvailabilityZoneName}` }).click();
  await expect(row(page, target.SubnetId!)).toHaveCount(0);
  await submit(page, "create-mount-target", { subnet: target.SubnetId! });
  await expect(row(page, target.SubnetId!)).toBeVisible();

  // File system policy from the template.
  await page.getByRole("link", { name: "File system policy" }).click();
  await submit(page, "edit-fs-policy");
  await expect(page.locator('pre[aria-label="File system policy"]')).toContainText("elasticfilesystem:ClientMount");
});
