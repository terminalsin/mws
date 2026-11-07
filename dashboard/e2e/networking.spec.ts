import { expect, test } from "@playwright/test";

import { row, rowAction, submit, unique } from "./helpers";

test("VPC: create a VPC with public and private subnets and see its resource map", async ({ page }) => {
  const name = unique("dash-vpc");
  await page.goto("/networking/vpc");
  await submit(page, "create-vpc", { name, cidr: "10.42.0.0/16", layout: "public-private" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const map = page.getByLabel("Resource map");
  await expect(map.locator(".map-node.public")).toHaveCount(2);
  await expect(map.locator(".map-node.private")).toHaveCount(2);
  await expect(map).toContainText(`${name}-igw`);

  await page.goto("/networking/vpc?tab=subnets");
  await expect(row(page, `${name}-subnet-public`).first()).toBeVisible();
});

test("Route 53: create a zone, add and delete a record", async ({ page }) => {
  const domain = `${unique("dash")}.example.com`;
  await page.goto("/networking/route53");
  await submit(page, "create-zone", { name: domain });
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  await submit(page, "create-record", { name: `www.${domain}`, type: "A", values: "192.0.2.10", ttl: "60" });
  await expect(row(page, "192.0.2.10")).toBeVisible();
  await rowAction(page, "192.0.2.10", /^Delete www/);
  await expect(row(page, "192.0.2.10")).toHaveCount(0);
});

test("Load balancers: an ALB with a listener forwarding to a target group", async ({ page }) => {
  const vpc = unique("dash-lbvpc");
  await page.goto("/networking/vpc");
  await submit(page, "create-vpc", { name: vpc, cidr: "10.43.0.0/16", layout: "public-private" });
  await expect(page.getByRole("heading", { level: 1, name: vpc })).toBeVisible();
  const vpcId = page.url().split("/").pop()!;

  const tg = unique("tg").slice(0, 32);
  await page.goto("/networking/elb?tab=targets");
  await submit(page, "create-target-group", { name: tg, targetType: "ip", vpc: vpcId });
  await expect(page.getByRole("heading", { level: 1, name: tg })).toBeVisible();

  const lb = unique("alb").slice(0, 32);
  await page.goto("/networking/elb");
  await submit(page, "create-load-balancer", { name: lb, vpc: vpcId });
  await expect(page.getByRole("heading", { level: 1, name: lb })).toBeVisible();
  await submit(page, "add-listener", { port: "8080" });
  await expect(row(page, ":8080")).toContainText(tg);
});

test("Certificates: a private CA issues a certificate requested through ACM", async ({ page }) => {
  const cn = unique("Dash Root CA");
  await page.goto("/networking/pca");
  await submit(page, "create-ca", { cn });
  await expect(page.getByRole("heading", { level: 1, name: cn })).toBeVisible();
  await submit(page, "install-ca-cert");
  await expect(page.locator(".specs")).toContainText("active");

  const domain = `${unique("svc")}.internal.example`;
  await page.goto("/networking/acm");
  await submit(page, "request-certificate", { domains: domain, pca: `Private · ${cn}` });
  await expect(page.getByRole("heading", { level: 1, name: domain })).toBeVisible();
  await expect(page.locator(".specs")).toContainText(/Issued|Pending/);
});

test("Global Accelerator: create an accelerator with a listener", async ({ page }) => {
  const name = unique("dash-ga");
  await page.goto("/networking/ga");
  await submit(page, "create-accelerator", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await submit(page, "add-ga-listener", { ports: "443" });
  await expect(page.getByRole("heading", { name: "TCP 443" })).toBeVisible();
});
