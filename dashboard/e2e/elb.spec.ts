import { expect, test, type Page } from "@playwright/test";

import { DescribeVpcsCommand, EC2Client } from "@aws-sdk/client-ec2";

import { row, sdk, submit, unique } from "./helpers";

/** The Region's default VPC (public subnets in every zone): MWS is shared,
 * and VPCs per Region are limited, so these tests do not make their own. */
async function defaultVpc() {
  const out = await new EC2Client(sdk).send(new DescribeVpcsCommand({ Filters: [{ Name: "is-default", Values: ["true"] }] }));
  return out.Vpcs![0].VpcId!;
}

test("Load balancers: an ALB with a listener forwarding to a target group", async ({ page }) => {
  const vpcId = await defaultVpc();

  const tg = unique("tg").slice(0, 32);
  await page.goto("/elb?tab=targets");
  await pick(page, "create-target-group", "tg-type-ip");
  await submit(page, "create-target-group", { name: tg, vpc: vpcId });
  await expect(page.getByRole("heading", { level: 1, name: tg })).toBeVisible();

  const lb = unique("alb").slice(0, 32);
  await page.goto("/elb");
  await submit(page, "create-load-balancer", { name: lb, vpc: vpcId });
  await expect(page.getByRole("heading", { level: 1, name: lb })).toBeVisible();
  const s = await sheet(page, "add-listener");
  await s.control("port").fill("8080");
  await s.form.getByLabel(new RegExp(tg)).check();
  await s.form.locator('button[type="submit"]').click();
  await expect(row(page, ":8080")).toContainText(tg);
});

/** Open the sheet holding form `testId` and pick one of its type tiles
 * (the fields below remount for it, so pick before filling). */
async function pick(page: Page, testId: string, tile: string) {
  const s = await sheet(page, testId);
  await s.form.getByTestId(tile).click();
  await expect(s.form.getByTestId(tile)).toHaveAttribute("aria-checked", "true");
  return s;
}

/** Open the sheet holding form `testId`; returns the form and a field getter. */
async function sheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  const control = (name: string) => form.locator(`[name="${name}"]`);
  return { form, field, control };
}

test("Load balancers: fields flag problems in place and offer repairs", async ({ page }) => {
  const vpcId = await defaultVpc();

  // Target group: a health check path without its leading slash.
  const tg = unique("tgv").slice(0, 32);
  await page.goto("/elb?tab=targets");
  let s = await pick(page, "create-target-group", "tg-type-ip");
  await s.control("healthPath").fill("health");
  await s.control("healthPath").blur();
  await expect(s.field("healthPath")).toHaveAttribute("data-invalid", "pattern");
  await s.field("healthPath").getByRole("button", { name: /Add \// }).click();
  await expect(s.control("healthPath")).toHaveValue("/health");
  await s.control("name").fill(tg);
  await s.control("vpc").selectOption(vpcId);
  await s.form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: tg })).toBeVisible();

  // Targets: an address outside the VPC comes back from MWS onto the field.
  s = await sheet(page, "register-targets");
  await s.control("targets").fill("10.99.0.5");
  await s.form.locator('button[type="submit"]').click();
  await expect(s.field("targets")).toHaveAttribute("data-invalid", "server");
  await expect(s.field("targets")).toContainText("not within the CIDR");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  // Not an address at all: flagged before submitting.
  await s.control("targets").fill("172.31.0");
  await s.control("targets").blur();
  await expect(s.field("targets")).toHaveAttribute("data-invalid", "pattern");

  // Load balancer: the reserved internal- prefix is dropped by a repair, and
  // a taken name suggests the next free one.
  await page.goto("/elb");
  const lb = unique("albv").slice(0, 26);
  s = await sheet(page, "create-load-balancer");
  await s.control("name").fill(`internal-${lb}`);
  await s.control("name").blur();
  await expect(s.field("name")).toHaveAttribute("data-invalid", "reserved");
  await s.field("name").getByRole("button", { name: /Drop internal-/ }).click();
  await expect(s.control("name")).toHaveValue(lb);
  await expect(s.field("name")).not.toHaveAttribute("data-invalid");
  await s.control("vpc").selectOption(vpcId);
  await s.form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name: lb })).toBeVisible();

  // Listener: HTTPS without a certificate lands on the certificate field...
  s = await sheet(page, "add-listener");
  await s.control("protocol").selectOption("HTTPS");
  await s.control("port").fill("443");
  await s.form.locator('button[type="submit"]').click();
  await expect(s.field("certificate")).toHaveAttribute("data-invalid", "required");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await s.control("protocol").selectOption("HTTP");
  await s.control("port").fill("8080");
  await s.form.getByLabel(new RegExp(tg)).check();
  await s.form.locator('button[type="submit"]').click();
  await expect(row(page, ":8080")).toContainText(tg);

  // ...and a port that is already listening offers the next free one.
  s = await sheet(page, "add-listener");
  await s.control("port").fill("8080");
  await s.control("port").blur();
  await expect(s.field("port")).toHaveAttribute("data-invalid", "taken");
  await s.field("port").getByRole("button", { name: /Use 8081/ }).click();
  await expect(s.control("port")).toHaveValue("8081");

  await page.goto("/elb");
  s = await sheet(page, "create-load-balancer");
  await s.control("name").fill(lb);
  await s.control("name").blur();
  await expect(s.field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(s.field("name").getByRole("button", { name: /Use / })).toContainText(`${lb}-2`);
});


test("Load balancers: listener rules with priorities, a modified listener, health checks and attributes", async ({ page }) => {
  const vpcId = await defaultVpc();
  const api = unique("tg-api").slice(0, 32);
  const web = unique("tg-web").slice(0, 32);
  for (const name of [web, api]) {
    await page.goto("/elb?tab=targets");
    await pick(page, "create-target-group", "tg-type-ip");
    await submit(page, "create-target-group", { name, vpc: vpcId });
    await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  }
  // Health check settings and attributes of the last group.
  await page.getByRole("link", { name: "Health checks" }).click();
  await submit(page, "edit-health-check", { hcPath: "/healthz", interval: "15", healthy: "3" });
  await expect(page.getByText("/healthz").first()).toBeVisible();
  await page.getByRole("link", { name: "Attributes" }).click();
  await submit(page, "tg-attributes", { "attr:deregistration_delay.timeout_seconds": "30" });
  await page.reload();
  await expect(page.locator('[name="attr:deregistration_delay.timeout_seconds"]')).toHaveValue("30");

  const lb = unique("alb-r").slice(0, 32);
  await page.goto("/elb");
  await submit(page, "create-load-balancer", { name: lb, vpc: vpcId });
  await expect(page.getByRole("heading", { level: 1, name: lb })).toBeVisible();
  await expect(page.getByText(/^Z[A-Z0-9]+$/).first()).toBeVisible();
  // A listener that forwards to web by default.
  const add = page.locator("dialog[open]").getByTestId("add-listener").and(page.locator("form"));
  await expect(async () => {
    if (!(await add.isVisible())) await page.getByTestId("add-listener-open").click();
    await expect(add).toBeVisible({ timeout: 1000 });
  }).toPass();
  await add.locator('[name="port"]').fill("8080");
  await add.getByLabel(new RegExp(web)).check();
  await add.locator('button[type="submit"]').click();
  await expect(row(page, ":8080")).toContainText(web);

  // Its page: a path rule to api, then a host rule, then swap their order.
  await row(page, ":8080").getByRole("link").click();
  await expect(page.getByRole("heading", { level: 1, name: "HTTP:8080" })).toBeVisible();
  const rule = page.locator("dialog[open]").getByTestId("add-rule").and(page.locator("form"));
  await expect(async () => {
    if (!(await rule.isVisible())) await page.getByTestId("add-rule-open").click();
    await expect(rule).toBeVisible({ timeout: 1000 });
  }).toPass();
  await rule.locator('[name="priority"]').fill("10");
  await rule.locator('[name="path"]').fill("/api/*");
  await rule.getByLabel(new RegExp(api)).check();
  await rule.locator('button[type="submit"]').click();
  await expect(row(page, "Path /api/*")).toContainText(api);
  await submit(page, "add-rule", { priority: "20", host: "admin.example.com", actionType: "fixed-response", fStatus: "403", fBody: "nope" });
  await expect(row(page, "Host admin.example.com")).toContainText("403");
  await row(page, "Host admin.example.com").getByRole("button", { name: "Move rule 20 up" }).click();
  await expect(row(page, "Host admin.example.com")).toContainText("10");
  await expect(row(page, "Path /api/*")).toContainText("20");
  // Edit a rule's priority.
  await submit(page, "edit-rule-20", { priority: "30" });
  await expect(row(page, "Path /api/*")).toContainText("30");

  // The listener itself: a redirect default action on another port.
  await submit(page, "edit-listener", { port: "8081", actionType: "redirect", rPort: "443" });
  await expect(page.getByRole("heading", { level: 1, name: "HTTP:8081" })).toBeVisible();
  await expect(page.getByText(/↪ HTTPS/).first()).toBeVisible();
});

test("Load balancers: Network and Gateway Load Balancers only forward; GENEVE groups; Classic", async ({ page }) => {
  const vpcId = await defaultVpc();
  const geneve = unique("tg-gnv").slice(0, 32);
  await page.goto("/elb?tab=targets");
  await pick(page, "create-target-group", "tg-type-ip");
  await submit(page, "create-target-group", { name: geneve, protocol: "GENEVE", vpc: vpcId });
  await expect(page.getByText("GENEVE:6081")).toBeVisible();

  const gw = unique("gwlb").slice(0, 32);
  await page.goto("/elb");
  await pick(page, "create-load-balancer", "lb-type-gateway");
  await submit(page, "create-load-balancer", { name: gw, vpc: vpcId });
  await expect(page.getByRole("heading", { level: 1, name: gw })).toBeVisible();
  const add = page.locator("dialog[open]").getByTestId("add-listener").and(page.locator("form"));
  await expect(async () => {
    if (!(await add.isVisible())) await page.getByTestId("add-listener-open").click();
    await expect(add).toBeVisible({ timeout: 1000 });
  }).toPass();
  // No fixed response on offer: only forward.
  await expect(add.locator('[name="actionType"]')).toHaveAttribute("type", "hidden");
  await add.getByLabel(new RegExp(geneve)).check();
  await add.locator('button[type="submit"]').click();
  await expect(row(page, "All traffic")).toContainText(geneve);

  const nlb = unique("nlb").slice(0, 32);
  await page.goto("/elb");
  await pick(page, "create-load-balancer", "lb-type-network");
  await submit(page, "create-load-balancer", { name: nlb, vpc: vpcId });
  await expect(page.getByRole("heading", { level: 1, name: nlb })).toBeVisible();
  const n = page.locator("dialog[open]").getByTestId("add-listener").and(page.locator("form"));
  await expect(async () => {
    if (!(await n.isVisible())) await page.getByTestId("add-listener-open").click();
    await expect(n).toBeVisible({ timeout: 1000 });
  }).toPass();
  await n.locator('button[type="submit"]').click();
  await expect(n.getByText("Choose a target group")).toBeVisible();

  const name = unique("clb").slice(0, 32);
  await page.goto("/elb?tab=classic");
  await submit(page, "create-classic", { name, vpc: vpcId, listeners: "HTTP:80 → HTTP:8080" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(row(page, ":80")).toContainText("HTTP:8080");
  await submit(page, "add-classic-listener", { listeners: "TCP:2222 → TCP:22" });
  await expect(row(page, ":2222")).toContainText("TCP:22");
  await submit(page, "classic-health", { target: "HTTP:8080/health" });
  await expect(page.getByText("HTTP:8080/health").first()).toBeVisible();
});
