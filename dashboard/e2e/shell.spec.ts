import { CloudWatchClient, PutMetricAlarmCommand, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { expect, test } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("home shows resources by service and the sidebar reaches every zone", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Home" })).toBeVisible();
  await expect(page.locator(".account")).toHaveText(/^\d{12}$/);

  // Each service outside the shell is a different Next.js app behind the
  // shell's rewrites; inside one, the sidebar is that service's own navigation.
  for (const [link, heading] of [
    ["S3", "Buckets"],
    ["SQS", "Queues"],
    ["IAM", "Users"],
    ["Lambda", "Functions"],
    ["CloudWatch", "Log groups"],
  ]) {
    await page.goto("/");
    await page.locator(".sidebar").getByRole("link", { name: link, exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  }
  await page.goto("/security/iam");
  await page.locator(".sidebar").getByRole("link", { name: "Roles", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Roles" })).toBeVisible();
  await expect(page.locator(".sidebar .nav-link.active")).toHaveText("Roles");

  // The Services menu reaches every service from anywhere.
  await page.getByRole("button", { name: "Services" }).click();
  await page.getByRole("menuitem", { name: "Lambda" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Functions" })).toBeVisible();
  await page.locator(".sidebar").getByRole("link", { name: "Control plane" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Control plane" })).toBeVisible();
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

test("feedback: a sheet's success becomes a toast, menus close with an exit, and / opens search", async ({ page }) => {
  const queue = unique("dash-toast");
  await page.goto("/messaging/sqs");
  await submit(page, "create-queue", { name: queue });
  const toast = page.locator(".toasts").getByRole("status").filter({ hasText: queue });
  await expect(toast).toBeVisible();
  await expect(toast).toHaveCount(0, { timeout: 10_000 });
  await expect(row(page, queue)).toBeVisible();

  // The navigation bar runs while the next page loads, then goes idle.
  await page.getByRole("link", { name: queue }).click();
  await expect(page.getByRole("heading", { level: 1, name: queue })).toBeVisible();
  await expect(page.locator(".route-progress")).toHaveAttribute("data-state", "idle");

  const services = page.getByRole("button", { name: "Services" });
  await services.click();
  await expect(page.getByRole("menu")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator(".services-panel")).toHaveAttribute("data-open", "false");
  await expect(page.getByRole("menu")).toBeHidden();

  await page.locator("body").press("/");
  const palette = page.getByRole("dialog", { name: "Search resources" });
  await expect(palette).toBeVisible();
  await expect(palette).not.toHaveAttribute("data-state", /loading|debouncing/);
  await palette.locator("input").press("Escape");
  await expect(palette).toBeHidden();
});

test("content appears without entry animations", async ({ page }) => {
  await page.goto("/messaging/sqs");
  await expect(page.getByRole("heading", { level: 1, name: "Queues" })).toBeVisible();
  const names = await page.locator(".content > :not(.page-skeleton), li.row").evaluateAll((els) => els.map((e) => getComputedStyle(e).animationName));
  expect(names.filter((n) => n !== "none")).toEqual([]);
});

test("motion respects reduced motion", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/messaging/sqs");
  const duration = await page.locator(".content > *").first().evaluate((e) => getComputedStyle(e).animationDuration);
  expect(duration).toBe("0.001s");
});
