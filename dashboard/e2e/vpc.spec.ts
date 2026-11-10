import { DeleteNatGatewayCommand, ReleaseAddressCommand, DescribeAddressesCommand, DescribeInternetGatewaysCommand, DescribeNatGatewaysCommand, DescribeRouteTablesCommand, DescribeVpcsCommand, EC2Client } from "@aws-sdk/client-ec2";
import { expect, test, type Page } from "@playwright/test";

import { row, rowAction, sdk, submit, unique } from "./helpers";

const ec2 = new EC2Client(sdk);

// MWS allows five VPCs per Region, as AWS does: every VPC a test makes is
// deleted after it, the way the console deletes one (NAT gateways first).
const made: string[] = [];
test.afterEach(async ({ page }) => {
  for (const id of made.splice(0)) {
    const nats = (await ec2.send(new DescribeNatGatewaysCommand({ Filter: [{ Name: "vpc-id", Values: [id] }] }))).NatGateways ?? [];
    for (const n of nats) {
      if (n.State === "deleted") continue;
      await ec2.send(new DeleteNatGatewayCommand({ NatGatewayId: n.NatGatewayId! }));
      // Addresses count against a quota of five, as in AWS.
      for (const a of n.NatGatewayAddresses ?? []) if (a.AllocationId) await ec2.send(new ReleaseAddressCommand({ AllocationId: a.AllocationId })).catch(() => {});
    }
    const still = await ec2.send(new DescribeVpcsCommand({ Filters: [{ Name: "vpc-id", Values: [id] }] }));
    if (!still.Vpcs?.length) continue;
    await page.goto(`/vpc/${id}`);
    page.once("dialog", (d) => d.accept().catch(() => {}));
    await page.getByTestId("delete-vpc").locator('button[type="submit"]').click();
    await expect(page).toHaveURL(/\/vpc$/);
  }
});

/** The VPC whose page is open. */
const opened = (page: Page) => {
  const id = new URL(page.url()).pathname.split("/")[2];
  made.push(id);
  return id;
};

test("VPC: create a VPC with public and private subnets and see its resource map", async ({ page }) => {
  const name = unique("dash-vpc");
  await page.goto("/vpc");
  await submit(page, "create-vpc", { name, cidr: "10.42.0.0/16", layout: "public-private" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  opened(page);
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
  opened(page);

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

/** Open the sheet behind `testId` (retrying until React has hydrated). */
async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  return form;
}

async function makeVpc(page: Page, name: string, layout = "public-private") {
  await page.goto("/vpc");
  await submit(page, "create-vpc", { name, layout });
  // "VPC and more" makes a dozen resources before the page opens.
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible({ timeout: 60_000 });
  return opened(page);
}

test("VPC: a VPC made with VPC and more deletes with its dependencies", async ({ page }) => {
  const name = unique("dash-vpc-del");
  const id = await makeVpc(page, name);
  made.splice(made.indexOf(id), 1);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-vpc").locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/\/vpc$/);
  await expect(row(page, name)).toHaveCount(0);
  const left = await ec2.send(new DescribeVpcsCommand({ Filters: [{ Name: "vpc-id", Values: [id] }] }));
  expect(left.Vpcs ?? []).toHaveLength(0);
});

test("VPC: route tables are created, associated, made main, edited and deleted", async ({ page }) => {
  const name = unique("dash-vpc-rtb");
  const vpc = await makeVpc(page, name);
  const table = `${name}-rtb-extra`;
  await submit(page, "create-route-table", { name: table });
  await page.goto("/vpc?tab=routes");
  await row(page, table).getByRole("link").click();
  await expect(page.getByRole("heading", { level: 1, name: table })).toBeVisible({ timeout: 30_000 });

  // A route to the VPC's internet gateway, then its target changed.
  const igw = (await ec2.send(new DescribeInternetGatewaysCommand({ Filters: [{ Name: "attachment.vpc-id", Values: [vpc] }] }))).InternetGateways![0].InternetGatewayId!;
  const rtb = page.url().split("id=")[1].split("&")[0];
  await submit(page, `add-route-${rtb}`, { destination: "172.16.0.0/12", target: igw });
  await expect(row(page, "172.16.0.0/12")).toContainText(igw);
  await row(page, "172.16.0.0/12").getByRole("button", { name: "Edit route 172.16.0.0/12" }).click();
  const edit = page.locator("dialog[open] form");
  await edit.locator('[name="target"]').fill(igw);
  await edit.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);

  // Move the private subnets onto it.
  await page.getByRole("link", { name: /^Subnet associations/ }).click();
  const form = await openSheet(page, "edit-associations");
  const boxes = form.locator('input[name="subnet"]');
  await expect(boxes).toHaveCount(4);
  for (const label of await form.locator("label.check").filter({ hasText: "subnet-private" }).all()) await label.locator("input").check();
  await form.locator('button[type="submit"]').click();
  await expect(page.getByLabel("Subnet associations").locator("li.row")).toHaveCount(2);

  // Make it the main table, then put the original main back and delete it.
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("set-main").locator('button[type="submit"]').click();
  await expect(page.getByTestId("set-main")).toHaveCount(0);
  const original = (await ec2.send(new DescribeRouteTablesCommand({ Filters: [{ Name: "vpc-id", Values: [vpc] }] }))).RouteTables!.find(
    (t) => t.RouteTableId !== rtb && !t.Tags?.some((x) => x.Key === "Name"),
  )!;
  await page.goto(`/vpc/rtb?id=${original.RouteTableId}`);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("set-main").locator('button[type="submit"]').click();
  await expect(page.getByTestId("set-main")).toHaveCount(0);
  // A table with subnets can't be deleted, as in AWS: move them back first.
  await page.goto(`/vpc/rtb?id=${rtb}&tab=subnets`);
  const associations = page.getByLabel("Subnet associations").locator("li.row");
  for (let i = 2; i > 0; i--) {
    page.once("dialog", (d) => d.accept().catch(() => {}));
    await associations.first().getByRole("button", { name: /^Disassociate / }).click();
    await expect(associations).toHaveCount(i - 1);
  }
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-route-table").locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/tab=routes/);
  await expect(row(page, table)).toHaveCount(0);
});

test("VPC: Elastic IPs are allocated, named, and released; a NAT gateway's EIP is released with it", async ({ page }) => {
  const name = unique("dash-eip");
  await page.goto("/vpc?tab=eips");
  await submit(page, "allocate-eip", { name });
  await expect(row(page, name)).toContainText("Unassociated");
  const ip = (await row(page, name).locator(".row-title").textContent())!.trim();
  await rowAction(page, name, `Release ${ip}`);
  await expect(row(page, name)).toHaveCount(0);

  // A NAT gateway in a public subnet allocates its own address...
  const vpcName = unique("dash-vpc-nat");
  const vpc = await makeVpc(page, vpcName);
  const form = await openSheet(page, "create-nat");
  await form.locator('[name="name"]').fill(`${vpcName}-nat`);
  if ((await form.getByTestId("nat-eip-auto").count()) === 0) await form.getByRole("button", { name: "Create automatically" }).click();
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  const nat = (await ec2.send(new DescribeNatGatewaysCommand({ Filter: [{ Name: "vpc-id", Values: [vpc] }] }))).NatGateways![0];
  const alloc = nat.NatGatewayAddresses![0].AllocationId!;
  await page.goto("/vpc?tab=eips");
  await expect(row(page, alloc)).toContainText(`${vpcName}-nat`);

  // ...and deleting it can release that address.
  await page.goto("/vpc?tab=nat");
  await submit(page, `delete-nat-${nat.NatGatewayId}`, { release: "on" });
  await expect(async () => {
    const left = await ec2.send(new DescribeAddressesCommand({ Filters: [{ Name: "allocation-id", Values: [alloc] }] })).catch(() => ({ Addresses: [] }));
    expect(left.Addresses ?? []).toHaveLength(0);
  }).toPass();
});

test("VPC: a peering request is accepted and deleted", async ({ page }) => {
  const a = unique("dash-pcx-a");
  const b = unique("dash-pcx-b");
  await makeVpc(page, a, "vpc");
  const peer = await makeVpc(page, b, "vpc");
  const vpcA = (await ec2.send(new DescribeVpcsCommand({ Filters: [{ Name: "tag:Name", Values: [a] }] }))).Vpcs![0].VpcId!;
  await page.goto("/vpc?tab=peering");
  const name = unique("dash-pcx");
  await submit(page, "create-peering", { name, vpc: vpcA, peer });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("pending-acceptance");
  const id = page.url().split("id=")[1];
  await page.getByRole("button", { name: `Accept ${id}` }).click();
  await expect(page.locator(".specs")).toContainText("active");
  await page.goto("/vpc?tab=peering");
  await rowAction(page, name, `Delete ${id}`);
  await expect(row(page, name)).toContainText(/deleted|deleting/);
});

test("VPC: network ACL rules are listed, added, edited and deleted", async ({ page }) => {
  const vpcName = unique("dash-vpc-acl");
  await makeVpc(page, vpcName);
  const name = unique("dash-acl");
  await page.goto("/vpc?tab=acls");
  await submit(page, "create-acl", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await submit(page, "add-acl-rule", { number: "100", protocol: "6", ports: "22", cidr: "203.0.113.0/24", action: "deny" });
  await expect(row(page, "203.0.113.0/24")).toContainText("Deny");
  await row(page, "203.0.113.0/24").getByRole("button", { name: "Edit rule 100" }).click();
  const edit = page.locator("dialog[open] form");
  await edit.locator('[name="action"]').selectOption("allow");
  await edit.locator('button[type="submit"]').click();
  await expect(row(page, "203.0.113.0/24")).toContainText("Allow");
  await rowAction(page, "203.0.113.0/24", "Delete rule 100");
  await expect(row(page, "203.0.113.0/24")).toHaveCount(0);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-acl").locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/tab=acls/);
});

test("VPC: an S3 gateway endpoint is created on a route table and deleted", async ({ page }) => {
  const vpcName = unique("dash-vpc-vpce");
  const vpc = await makeVpc(page, vpcName);
  await page.goto("/vpc?tab=endpoints");
  const form = await openSheet(page, "create-endpoint");
  const name = unique("dash-vpce");
  await form.locator('[name="name"]').fill(name);
  const s3 = await form.locator('[name="service"] option').filter({ hasText: /\.s3$/ }).first().getAttribute("value");
  await form.locator('[name="service"]').selectOption(s3!);
  await form.locator('[name="type"]').selectOption("Gateway");
  await form.locator('[name="vpc"]').selectOption(vpc);
  await form.locator("label.check").filter({ hasText: `${vpcName}-rtb-public` }).locator("input").check();
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.getByRole("list", { name: "Route tables" })).toContainText(`${vpcName}-rtb-public`);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByTestId("delete-endpoint").locator('button[type="submit"]').click();
  await expect(page).toHaveURL(/tab=endpoints/);
});
