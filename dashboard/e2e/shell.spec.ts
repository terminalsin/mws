import { expect, test } from "@playwright/test";

import { submit, unique } from "./helpers";

test("the overview shows MWS and links to every zone", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByTestId("services")).toContainText("s3");
  await expect(page.getByTestId("services")).toContainText("sqs");
  await expect(page.locator(".topbar")).toContainText(/Account\s*\d{12}/);

  // Each sidebar entry outside the shell is a different Next.js app behind
  // the shell's rewrites.
  for (const [link, heading] of [
    ["S3 buckets", "S3 buckets"],
    ["SQS queues", "SQS queues"],
    ["IAM", "IAM"],
    ["Lambda functions", "Lambda functions"],
    ["Log groups", "Log groups"],
    ["Control plane", "Control plane"],
  ]) {
    await page.locator(".sidebar").getByRole("link", { name: link, exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  }
});

test("the region picker applies to every zone", async ({ page }) => {
  const queue = unique("dash-region");
  await page.goto("/messaging/sqs");
  await page.getByLabel("Region", { exact: true }).selectOption("eu-west-1");
  await expect(page.getByLabel("Region", { exact: true })).toHaveValue("eu-west-1");
  await submit(page, "create-queue", { name: queue });
  await expect(page.getByRole("link", { name: queue })).toBeVisible();

  // The cookie is shared by all zones, so the storage zone sees it too.
  await page.goto("/storage/s3");
  await expect(page.getByLabel("Region", { exact: true })).toHaveValue("eu-west-1");

  await page.goto("/messaging/sqs");
  await page.getByLabel("Region", { exact: true }).selectOption("us-east-1");
  await expect(page.getByRole("link", { name: queue })).toHaveCount(0);
});

test("snapshots and the emulated clock", async ({ page }) => {
  const name = unique("dash-snap");
  await page.goto("/control");
  await submit(page, "save-snapshot", { name });
  await expect(page.getByRole("row").filter({ hasText: name })).toBeVisible();

  await submit(page, "advance-clock", { amount: "2", unit: "hours" });
  await expect(page.getByText("+7200s")).toBeVisible();
  await page.getByRole("button", { name: "Back to real time" }).click();
  await expect(page.getByText("real time", { exact: true })).toBeVisible();

  page.once("dialog", (d) => d.accept());
  await page.getByRole("row").filter({ hasText: name }).getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("row").filter({ hasText: name })).toHaveCount(0);
});

test("state export downloads a JSON document", async ({ request }) => {
  const response = await request.get("/control/state");
  expect(response.ok()).toBeTruthy();
  expect(response.headers()["content-disposition"]).toContain("mws-state-");
  expect(typeof (await response.json())).toBe("object");
});
