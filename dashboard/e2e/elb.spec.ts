import { expect, test } from "@playwright/test";

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
