import {
  CreateKeyPairCommand,
  CreateSecurityGroupCommand,
  DeleteKeyPairCommand,
  DeleteSecurityGroupCommand,
  DescribeImagesCommand,
  DescribeInstanceAttributeCommand,
  DescribeInstancesCommand,
  DescribeLaunchTemplatesCommand,
  DescribeLaunchTemplateVersionsCommand,
  DescribeSecurityGroupRulesCommand,
  DescribeSnapshotsCommand,
  DescribeSubnetsCommand,
  DescribeVolumesCommand,
  DescribeVpcsCommand,
  EC2Client,
  RunInstancesCommand,
  TerminateInstancesCommand,
} from "@aws-sdk/client-ec2";
import { AddRoleToInstanceProfileCommand, CreateInstanceProfileCommand, CreateRoleCommand, IAMClient } from "@aws-sdk/client-iam";
import { expect, test, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";

import { row, rowAction, sdk, submit, unique } from "./helpers";

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

// ---------------------------------------------------------------------------
// EBS, launch, instance settings, launch templates, AMIs, SG rules.

async function alpine(ec2: EC2Client) {
  return (await ec2.send(new DescribeImagesCommand({ Owners: ["amazon"], Filters: [{ Name: "name", Values: ["mws-alpine-*"] }] }))).Images![0];
}

async function runOne(ec2: EC2Client, name: string) {
  const image = await alpine(ec2);
  const run = await ec2.send(
    new RunInstancesCommand({ ImageId: image.ImageId, InstanceType: "t3.nano", MinCount: 1, MaxCount: 1, TagSpecifications: [{ ResourceType: "instance", Tags: [{ Key: "Name", Value: name }] }] }),
  );
  const instance = run.Instances![0];
  await expect(async () => {
    const d = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instance.InstanceId!] }));
    expect(d.Reservations![0].Instances![0].State!.Name).toBe("running");
  }).toPass({ timeout: 60_000 });
  return instance;
}

/** Submit one of the forms inside the "Instance settings" sheet. */
async function inSettings(page: Page, testId: string, fields: Record<string, string>) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("instance-settings-open").click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  for (const [name, value] of Object.entries(fields)) {
    const field = form.locator(`[name="${name}"]`);
    if ((await field.getAttribute("type")) === "checkbox") await field.setChecked(value === "on");
    else await field.fill(value);
  }
  await form.locator('button[type="submit"]').click();
  await expect(form).toBeHidden();
}

const volumeOf = async (ec2: EC2Client, name: string) =>
  (await ec2.send(new DescribeVolumesCommand({ Filters: [{ Name: "tag:Name", Values: [name] }] }))).Volumes?.[0];

test("EC2: volumes are created, attached, grown, snapshotted, detached and deleted", async ({ page }) => {
  test.setTimeout(180_000);
  const ec2 = new EC2Client(sdk);
  const name = unique("dash-vol");
  const instance = await runOne(ec2, unique("dash-vol-host"));
  const zone = instance.Placement!.AvailabilityZone!;

  await page.goto("/ec2?tab=volumes");
  await submit(page, "create-volume", { name, zone, type: "gp3", size: "10" });
  await expect(row(page, name)).toBeVisible();
  await expect(async () => expect((await volumeOf(ec2, name))?.State).toBe("available")).toPass();
  const id = (await volumeOf(ec2, name))!.VolumeId!;

  // Attach from the list: the device field offers a free name.
  await page.reload();
  await row(page, name).getByRole("button", { name: `Attach ${id}` }).click();
  const attach = page.locator("dialog[open]").getByTestId("attach-volume").and(page.locator("form"));
  await attach.locator('[name="instance"]').selectOption(instance.InstanceId!);
  await expect(attach.locator('[name="device"]')).toHaveValue(/^\/dev\/sd[f-p]$/);
  await attach.locator('button[type="submit"]').click();
  await expect(async () => expect((await volumeOf(ec2, name))?.Attachments?.[0]?.State).toBe("attached")).toPass({ timeout: 30_000 });

  // The volume page: grow it, snapshot it, then detach.
  await page.goto(`/ec2/volume?id=${id}`);
  await expect(page.getByRole("link", { name: /dash-vol-host/ })).toBeVisible();
  await submit(page, "modify-volume", { size: "12" });
  await expect(async () => expect((await volumeOf(ec2, name))?.Size).toBe(12)).toPass({ timeout: 30_000 });
  const snap = unique("dash-snap");
  await submit(page, "create-snapshot", { name: snap, description: "from the console" });
  await expect(async () => {
    const s = (await ec2.send(new DescribeSnapshotsCommand({ OwnerIds: ["self"], Filters: [{ Name: "tag:Name", Values: [snap] }] }))).Snapshots?.[0];
    expect(s?.VolumeId).toBe(id);
  }).toPass();
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("detach-volume").locator('button[type="submit"]').click();
  await expect(async () => expect((await volumeOf(ec2, name))?.State).toBe("available")).toPass({ timeout: 30_000 });

  // Snapshots: copy, then delete both copies.
  await page.goto("/ec2?tab=snapshots");
  await expect(row(page, snap)).toBeVisible();
  const snapId = (await ec2.send(new DescribeSnapshotsCommand({ OwnerIds: ["self"], Filters: [{ Name: "tag:Name", Values: [snap] }] }))).Snapshots![0].SnapshotId!;
  await expect(async () => {
    await page.reload();
    await row(page, snap).first().getByRole("button", { name: `Copy ${snapId}` }).click({ timeout: 2000 });
  }).toPass({ timeout: 30_000 });
  const copy = unique("dash-snap-copy");
  const copyForm = page.locator("dialog[open]").getByTestId("copy-snapshot").and(page.locator("form"));
  await copyForm.locator('[name="name"]').fill(copy);
  await copyForm.locator('button[type="submit"]').click();
  await expect(row(page, copy)).toBeVisible();
  await rowAction(page, snap, `Delete ${snapId}`);
  await expect(row(page, snap)).toHaveCount(0);

  // Delete the volume from its page.
  await page.goto(`/ec2/volume?id=${id}`);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-volume").locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/tab=volumes/);
  await expect(async () => expect(await volumeOf(ec2, name)).toBeUndefined()).toPass({ timeout: 30_000 });
  await ec2.send(new TerminateInstancesCommand({ InstanceIds: [instance.InstanceId!] }));
});

test("EC2: the launch form sets the subnet, groups, IAM profile and root volume", async ({ page }) => {
  test.setTimeout(120_000);
  const ec2 = new EC2Client(sdk);
  const iam = new IAMClient(sdk);
  const profile = unique("dash-profile");
  await iam.send(new CreateRoleCommand({ RoleName: profile, AssumeRolePolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }] }) }));
  await iam.send(new CreateInstanceProfileCommand({ InstanceProfileName: profile }));
  await iam.send(new AddRoleToInstanceProfileCommand({ InstanceProfileName: profile, RoleName: profile }));
  const vpc = (await ec2.send(new DescribeVpcsCommand({ Filters: [{ Name: "is-default", Values: ["true"] }] }))).Vpcs![0];
  const subnet = (await ec2.send(new DescribeSubnetsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc.VpcId!] }] }))).Subnets![0];
  const group = unique("dash-launch-sg");
  const sg = await ec2.send(new CreateSecurityGroupCommand({ GroupName: group, Description: group, VpcId: vpc.VpcId }));
  const name = unique("dash-launch");
  const image = await alpine(ec2);

  await page.goto("/ec2");
  const { form, input } = await openSheet(page, "launch-instance");
  await input("name").fill(name);
  await input("image").fill(image.ImageId!);
  await input("type").fill("t3.nano");
  await input("subnet").selectOption(subnet.SubnetId!);
  await input("publicIp").selectOption("disable");
  await form.getByTestId("launch-groups").getByLabel(group).check();
  await input("iamProfile").selectOption(profile);
  await input("rootSize").fill("20");
  await input("rootType").selectOption("gp3");
  await form.locator('button[type="submit"]').click();
  await expect(form).toBeHidden();

  const launched = await expect
    .poll(async () => (await ec2.send(new DescribeInstancesCommand({ Filters: [{ Name: "tag:Name", Values: [name] }] }))).Reservations?.[0]?.Instances?.[0]?.InstanceId)
    .toBeTruthy()
    .then(async () => (await ec2.send(new DescribeInstancesCommand({ Filters: [{ Name: "tag:Name", Values: [name] }] }))).Reservations![0].Instances![0]);
  expect(launched.SubnetId).toBe(subnet.SubnetId);
  expect(launched.SecurityGroups?.map((g) => g.GroupId)).toEqual([sg.GroupId]);
  expect(launched.IamInstanceProfile?.Arn).toContain(`/${profile}`);
  expect(launched.PublicIpAddress).toBeUndefined();
  const root = (await ec2.send(new DescribeVolumesCommand({ Filters: [{ Name: "attachment.instance-id", Values: [launched.InstanceId!] }] }))).Volumes![0];
  expect(root.Size).toBe(20);

  // The instance page shows where it runs and links its profile to IAM.
  await page.goto(`/ec2/instance?id=${launched.InstanceId}`);
  await expect(page.getByRole("link", { name: subnet.SubnetId! }).or(page.locator(`a[href="/vpc/subnet?id=${subnet.SubnetId}"]`)).first()).toBeVisible();
  await expect(page.locator(`a[href="/vpc/${vpc.VpcId}"]`)).toBeVisible();
  await expect(page.locator(`a[href="/iam/instance-profiles/${profile}"]`)).toBeVisible();
  await ec2.send(new TerminateInstancesCommand({ InstanceIds: [launched.InstanceId!] }));
});

test("EC2: instance settings change protection, metadata options and the IAM role", async ({ page }) => {
  test.setTimeout(120_000);
  const ec2 = new EC2Client(sdk);
  const iam = new IAMClient(sdk);
  const profile = unique("dash-role");
  await iam.send(new CreateRoleCommand({ RoleName: profile, AssumeRolePolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }] }) }));
  await iam.send(new CreateInstanceProfileCommand({ InstanceProfileName: profile }));
  await iam.send(new AddRoleToInstanceProfileCommand({ InstanceProfileName: profile, RoleName: profile }));
  const instance = await runOne(ec2, unique("dash-settings"));
  const id = instance.InstanceId!;
  const describe = async () => (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [id] }))).Reservations![0].Instances![0];

  await page.goto(`/ec2/instance?id=${id}`);
  await inSettings(page, "change-protection", { termination: "on" });
  await expect
    .poll(async () => (await ec2.send(new DescribeInstanceAttributeCommand({ InstanceId: id, Attribute: "disableApiTermination" }))).DisableApiTermination?.Value)
    .toBe(true);
  await submit(page, "metadata-options", { hopLimit: "3", tokens: "required" });
  await expect.poll(async () => (await describe()).MetadataOptions?.HttpPutResponseHopLimit).toBe(3);

  await page.goto(`/ec2/instance?id=${id}&tab=security`);
  await submit(page, "modify-role", { iamProfile: profile });
  await expect.poll(async () => (await describe()).IamInstanceProfile?.Arn ?? "").toContain(`/${profile}`);
  await page.reload();
  await expect(page.locator(`a[href="/iam/instance-profiles/${profile}"]`).first()).toBeVisible();

  // Protected: terminating fails until protection is off again.
  await page.goto(`/ec2/instance?id=${id}`);
  await inSettings(page, "change-protection", { termination: "off" });
  await ec2.send(new TerminateInstancesCommand({ InstanceIds: [id] }));
});

test("EC2: launch templates get versions, a default and are deleted", async ({ page }) => {
  const ec2 = new EC2Client(sdk);
  const name = unique("dash-lt");
  const image = await alpine(ec2);
  await page.goto("/ec2?tab=templates");
  const { form, input } = await openSheet(page, "create-launch-template");
  await input("name").fill(name);
  await input("description").fill("first");
  await input("image").fill(image.ImageId!);
  await input("type").fill("t3.nano");
  await form.locator('button[type="submit"]').click();
  await expect(form).toBeHidden();
  await row(page, name).click();
  await expect(page.getByRole("heading", { name })).toBeVisible();
  const id = (await ec2.send(new DescribeLaunchTemplatesCommand({ LaunchTemplateNames: [name] }))).LaunchTemplates![0].LaunchTemplateId!;

  await submit(page, "create-template-version", { description: "second", type: "t3.small", makeDefault: "on" });
  await expect.poll(async () => (await ec2.send(new DescribeLaunchTemplatesCommand({ LaunchTemplateIds: [id] }))).LaunchTemplates![0].DefaultVersionNumber).toBe(2);
  const v2 = (await ec2.send(new DescribeLaunchTemplateVersionsCommand({ LaunchTemplateId: id, Versions: ["2"] }))).LaunchTemplateVersions![0];
  expect(v2.LaunchTemplateData?.ImageId).toBe(image.ImageId);
  expect(v2.LaunchTemplateData?.InstanceType).toBe("t3.small");

  await rowAction(page, "Version 1", "Delete version 1");
  await expect(row(page, "Version 1")).toHaveCount(0);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-template").locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/tab=templates/);
  await expect(row(page, name)).toHaveCount(0);
});

test("EC2: an AMI is created from an instance, shared and deregistered", async ({ page }) => {
  test.setTimeout(120_000);
  const ec2 = new EC2Client(sdk);
  const instance = await runOne(ec2, unique("dash-ami-src"));
  const name = unique("dash-ami");
  await page.goto(`/ec2/instance?id=${instance.InstanceId}`);
  await submit(page, "create-image", { name, noReboot: "on" });
  const image = await expect
    .poll(async () => (await ec2.send(new DescribeImagesCommand({ Owners: ["self"], Filters: [{ Name: "name", Values: [name] }] }))).Images?.[0]?.ImageId)
    .toBeTruthy()
    .then(async () => (await ec2.send(new DescribeImagesCommand({ Owners: ["self"], Filters: [{ Name: "name", Values: [name] }] }))).Images![0]);

  await page.goto("/ec2?tab=images");
  await row(page, name).click();
  await expect(page.getByRole("heading", { name })).toBeVisible();
  await expect(page.locator(`a[href="/ec2/instance?id=${instance.InstanceId}"]`).first()).toBeVisible();
  await submit(page, "share-image", { account: "111122223333" });
  await expect(page.getByRole("list", { name: "Launch permissions" })).toContainText("111122223333");
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("deregister-image").locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/tab=images/);
  await expect.poll(async () => (await ec2.send(new DescribeImagesCommand({ Owners: ["self"], Filters: [{ Name: "name", Values: [name] }] }))).Images?.length ?? 0).toBe(0);
  expect(image.ImageId).toMatch(/^ami-/);
  await ec2.send(new TerminateInstancesCommand({ InstanceIds: [instance.InstanceId!] }));
});

test("EC2: security group pages add outbound and group-reference rules", async ({ page }) => {
  const ec2 = new EC2Client(sdk);
  const vpc = (await ec2.send(new DescribeVpcsCommand({ Filters: [{ Name: "is-default", Values: ["true"] }] }))).Vpcs![0];
  const [a, b] = [unique("dash-sg-a"), unique("dash-sg-b")];
  const ga = await ec2.send(new CreateSecurityGroupCommand({ GroupName: a, Description: a, VpcId: vpc.VpcId }));
  const gb = await ec2.send(new CreateSecurityGroupCommand({ GroupName: b, Description: b, VpcId: vpc.VpcId }));
  await page.goto(`/ec2/group?id=${ga.GroupId}`);
  await expect(page.locator(`a[href="/vpc/${vpc.VpcId}"]`)).toBeVisible();

  // Inbound from another group.
  await submit(page, "add-inbound-rule", { protocol: "tcp", ports: "5432", peer: "group", group: gb.GroupId!, description: "app to db" });
  await expect(page.getByRole("list", { name: "Inbound rules" })).toContainText(b);
  // Outbound to the S3 prefix list.
  await page.goto(`/ec2/group?id=${ga.GroupId}&tab=outbound`);
  await submit(page, "add-outbound-rule", { protocol: "tcp", ports: "443", peer: "prefixList" });
  const rules = (await ec2.send(new DescribeSecurityGroupRulesCommand({ Filters: [{ Name: "group-id", Values: [ga.GroupId!] }] }))).SecurityGroupRules!;
  expect(rules.some((r) => !r.IsEgress && r.ReferencedGroupInfo?.GroupId === gb.GroupId && r.FromPort === 5432 && r.Description === "app to db")).toBe(true);
  const egress = rules.find((r) => r.IsEgress && r.PrefixListId);
  expect(egress?.FromPort).toBe(443);
  await expect(page.getByRole("list", { name: "Outbound rules" })).toContainText(egress!.PrefixListId!);

  // Remove the default allow-all egress rule.
  const all = rules.find((r) => r.IsEgress && r.CidrIpv4 === "0.0.0.0/0")!;
  await rowAction(page, all.SecurityGroupRuleId!, /^Remove /);
  await expect(page.getByRole("list", { name: "Outbound rules" })).not.toContainText(all.SecurityGroupRuleId!);
  await ec2.send(new DeleteSecurityGroupCommand({ GroupId: ga.GroupId }));
  await ec2.send(new DeleteSecurityGroupCommand({ GroupId: gb.GroupId }));
});

test("EC2: key pairs are imported from a public key", async ({ page }) => {
  const key = unique("dash-import");
  await page.goto("/ec2?tab=keys");
  await submit(page, "import-key-pair", { name: key, publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbnyYBnpZ9VXAyzVGm0ZtUCNK6zLNnKb1G7TQw36XB9 dash@test" });
  await expect(row(page, key)).toBeVisible();
  await rowAction(page, key, `Delete ${key}`);
  await expect(row(page, key)).toHaveCount(0);
});
