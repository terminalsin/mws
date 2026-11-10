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
