import { expect, test } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("VPC: create a VPC with public and private subnets and see its resource map", async ({ page }) => {
  const name = unique("dash-vpc");
  await page.goto("/vpc");
  await submit(page, "create-vpc", { name, cidr: "10.42.0.0/16", layout: "public-private" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const map = page.getByLabel("Resource map");
  await expect(map.locator(".map-node.public")).toHaveCount(2);
  await expect(map.locator(".map-node.private")).toHaveCount(2);
  await expect(map).toContainText(`${name}-igw`);

  await page.goto("/vpc?tab=subnets");
  await expect(row(page, `${name}-subnet-public`).first()).toBeVisible();
});

test("VPC: CIDR and route fields check the netmask, the VPC, its subnets and routes, with repairs", async ({ page }) => {
  const name = unique("dash-vpc-cidr");
  // Too large a VPC: the netmask is clamped in one click.
  await page.goto("/vpc");
  const dialog = page.locator("dialog[open]");
  await expect(async () => {
    if (!(await dialog.isVisible())) await page.getByTestId("create-vpc-open").first().click();
    await expect(dialog).toBeVisible({ timeout: 1000 });
  }).toPass();
  const vpcCidr = dialog.locator('input[name="cidr"]');
  const vpcField = dialog.locator(".field").filter({ has: page.locator('input[name="cidr"]') });
  // The suggested block is a free /16.
  await expect(vpcCidr).toHaveValue(/^10\.\d+\.0\.0\/16$/);
  await dialog.locator('input[name="name"]').fill(name);
  await vpcCidr.fill("10.0.0.0/8");
  await vpcCidr.blur();
  await expect(vpcField).toHaveAttribute("data-invalid", "format");
  await expect(vpcField).toContainText("Netmask /16 to /26");
  await vpcField.getByRole("button", { name: /10\.0\.0\.0\/16/ }).click();
  await expect(vpcCidr).toHaveValue("10.0.0.0/16");
  await expect(vpcField).not.toHaveAttribute("data-invalid");
  await vpcCidr.fill("10.77.0.0/16");
  await dialog.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();

  // A subnet on the VPC's page starts at its first free block...
  await expect(async () => {
    if (!(await dialog.isVisible())) await page.getByTestId("create-subnet-open").first().click();
    await expect(dialog).toBeVisible({ timeout: 1000 });
  }).toPass();
  const cidr = dialog.locator('input[name="cidr"]');
  const field = dialog.locator(".field").filter({ has: page.locator('input[name="cidr"]') });
  await expect(cidr).toHaveValue("10.77.64.0/20");
  // ...flags blocks outside the VPC or overlapping a subnet, with free ones.
  await cidr.fill("10.78.0.0/20");
  await cidr.blur();
  await expect(field).toContainText("Outside 10.77.0.0/16");
  await cidr.fill("10.77.0.0/24");
  await cidr.blur();
  await expect(field).toContainText("Overlaps 10.77.0.0/20");
  await field.getByRole("button", { name: /10\.77\.64\.0\/24/ }).click();
  await expect(cidr).toHaveValue("10.77.64.0/24");
  await expect(field).not.toHaveAttribute("data-invalid");
  // Host bits set: the network address.
  await cidr.fill("10.77.64.9/24");
  await cidr.blur();
  await field.getByRole("button", { name: /Use the network address/ }).click();
  await expect(cidr).toHaveValue("10.77.64.0/24");
  await dialog.locator('button[type="submit"]').click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByLabel("Resource map").locator(".map-node.private")).toHaveCount(3);

  // Routes: a destination the table has is flagged before submitting.
  // The public table already sends 0.0.0.0/0 to the internet gateway.
  const table = page.locator('[id^="rtb-"]').filter({ hasText: `${name}-rtb-public` });
  await expect(async () => {
    if (!(await dialog.isVisible())) await table.getByTestId(/^add-route-.*-open$/).click();
    await expect(dialog).toBeVisible({ timeout: 1000 });
  }).toPass();
  const dest = dialog.locator('input[name="destination"]');
  const destField = dialog.locator(".field").filter({ has: page.locator('input[name="destination"]') });
  await dialog.locator('button[type="submit"]').click();
  await expect(destField).toHaveAttribute("data-invalid", "taken");
  await expect(dest).toBeFocused();

  // A mistyped target is offered the gateways this VPC has.
  const target = dialog.locator('input[name="target"]');
  const targetField = dialog.locator(".field").filter({ has: page.locator('input[name="target"]') });
  const igw = await target.inputValue();
  expect(igw).toMatch(/^igw-/);
  await target.fill(`${igw}x`);
  await target.blur();
  await expect(targetField).toHaveAttribute("data-invalid", "pattern");
  await targetField.getByRole("button", { name: new RegExp(igw) }).click();
  await expect(target).toHaveValue(igw);

  // A new destination goes through.
  await dest.fill("192.168.0.0/16");
  await dialog.locator('button[type="submit"]').click();
  await expect(dialog).toHaveCount(0);
  await expect(table).toContainText("192.168.0.0/16");
});
