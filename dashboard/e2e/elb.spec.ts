import { expect, test, type Page } from "@playwright/test";

import { row, submit, unique } from "./helpers";

test("Load balancers: an ALB with a listener forwarding to a target group", async ({ page }) => {
  const vpc = unique("dash-lbvpc");
  await page.goto("/vpc");
  await submit(page, "create-vpc", { name: vpc, cidr: "10.43.0.0/16", layout: "public-private" });
  await expect(page.getByRole("heading", { level: 1, name: vpc })).toBeVisible();
  const vpcId = page.url().split("/").pop()!;

  const tg = unique("tg").slice(0, 32);
  await page.goto("/elb?tab=targets");
  await submit(page, "create-target-group", { name: tg, targetType: "ip", vpc: vpcId });
  await expect(page.getByRole("heading", { level: 1, name: tg })).toBeVisible();

  const lb = unique("alb").slice(0, 32);
  await page.goto("/elb");
  await submit(page, "create-load-balancer", { name: lb, vpc: vpcId });
  await expect(page.getByRole("heading", { level: 1, name: lb })).toBeVisible();
  await submit(page, "add-listener", { port: "8080" });
  await expect(row(page, ":8080")).toContainText(tg);
});

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
  const vpc = unique("dash-lbval");
  await page.goto("/vpc");
  await submit(page, "create-vpc", { name: vpc, cidr: "10.44.0.0/16", layout: "public-private" });
  await expect(page.getByRole("heading", { level: 1, name: vpc })).toBeVisible();
  const vpcId = page.url().split("/").pop()!;

  // Target group: a health check path without its leading slash.
  const tg = unique("tgv").slice(0, 32);
  await page.goto("/elb?tab=targets");
  let s = await sheet(page, "create-target-group");
  await s.control("healthPath").fill("health");
  await s.control("healthPath").blur();
  await expect(s.field("healthPath")).toHaveAttribute("data-invalid", "pattern");
  await s.field("healthPath").getByRole("button", { name: /Add \// }).click();
  await expect(s.control("healthPath")).toHaveValue("/health");
  await s.control("name").fill(tg);
  await s.control("targetType").selectOption("ip");
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
  await s.control("targets").fill("10.44.0");
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
