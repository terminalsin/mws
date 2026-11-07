import { CloudWatchClient, PutMetricAlarmCommand, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { expect, test } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("home shows resources by service and the sidebar reaches every zone", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Home" })).toBeVisible();
  await expect(page.locator(".account")).toHaveText(/^\d{12}$/);

  // Each sidebar entry outside the shell is a different Next.js app behind
  // the shell's rewrites.
  for (const [link, heading] of [
    ["S3", "S3"],
    ["SQS", "SQS"],
    ["IAM", "IAM"],
    ["Lambda", "Lambda"],
    ["CloudWatch", "Logs"],
    ["Control plane", "Control plane"],
  ]) {
    await page.locator(".sidebar").getByRole("link", { name: link, exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  }
});

test("an alarm firing anywhere shows on the home page", async ({ page }) => {
  const alarm = unique("dash-home-alarm");
  const cw = new CloudWatchClient(sdk);
  await cw.send(new PutMetricDataCommand({ Namespace: "Dash/Home", MetricData: [{ MetricName: "Errors", Value: 5 }] }));
  // A real breach (MWS re-evaluates alarms, so a forced state would not last).
  await cw.send(
    new PutMetricAlarmCommand({
      AlarmName: alarm,
      Namespace: "Dash/Home",
      MetricName: "Errors",
      Statistic: "Sum",
      Period: 60,
      EvaluationPeriods: 1,
      Threshold: 1,
      ComparisonOperator: "GreaterThanThreshold",
      TreatMissingData: "breaching",
    }),
  );
  // The shell caches the inventory for a few seconds.
  await expect(async () => {
    await page.goto("/");
    await expect(page.getByRole("list", { name: "Needs attention" })).toContainText(alarm, { timeout: 1000 });
  }).toPass({ timeout: 90_000 });
});

test("⌘K finds resources across zones", async ({ page }) => {
  const queue = unique("dash-findme");
  await page.goto("/messaging/sqs");
  await submit(page, "create-queue", { name: queue });

  await page.goto("/");
  await page.getByRole("button", { name: "Search" }).click();
  const input = page.getByRole("dialog").locator("input");
  await input.fill(queue);
  const hit = page.getByRole("dialog").getByRole("option", { name: new RegExp(queue) });
  await expect(hit).toBeVisible();
  await input.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/messaging/sqs/${queue}`));
  await expect(page.getByRole("heading", { level: 1, name: queue })).toBeVisible();
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
  await expect(row(page, name)).toBeVisible();

  await submit(page, "advance-clock", { amount: "2", unit: "hours" });
  await page.reload();
  await expect(page.getByText("+2h")).toBeVisible();
  await page.getByRole("button", { name: "Back to real time" }).click();
  await expect(page.getByText("Real time", { exact: true })).toBeVisible();

  page.once("dialog", (d) => d.accept().catch(() => {}));
  await row(page, name).getByRole("button", { name: `Delete ${name}` }).click();
  await expect(row(page, name)).toHaveCount(0);
});

test("state export downloads a JSON document", async ({ request }) => {
  const response = await request.get("/control/state");
  expect(response.ok()).toBeTruthy();
  expect(response.headers()["content-disposition"]).toContain("mws-state-");
  expect(typeof (await response.json())).toBe("object");
});
