import { CloudWatchClient, PutMetricAlarmCommand, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { expect, test } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("Logs: create a group, write and search events", async ({ page }) => {
  const group = `/dash/${unique("app")}`;
  await page.goto("/logs");
  await submit(page, "create-log-group", { name: group, retention: "14" });
  await expect(row(page, group)).toContainText("14 days");
  await page.getByRole("link", { name: group }).click();
  await submit(page, "write-event", { message: "ERROR something broke" });
  await submit(page, "write-event", { message: "INFO all good" });
  await page.reload();
  const events = page.getByRole("list", { name: "Log events" });
  await expect(events).toContainText("INFO all good");
  await expect(events.locator("li.bad")).toContainText("ERROR something broke");

  await page.getByLabel("Filter pattern").fill("ERROR");
  await page.getByLabel("Filter pattern").press("Enter");
  await expect(events).toContainText("ERROR something broke");
  await expect(events).not.toContainText("INFO all good");
});

test("CloudWatch: metrics chart and alarm state", async ({ page }) => {
  const namespace = unique("Dash");
  const alarm = unique("dash-alarm");
  const cw = new CloudWatchClient(sdk);
  await cw.send(new PutMetricDataCommand({ Namespace: namespace, MetricData: [{ MetricName: "Orders", Value: 3 }, { MetricName: "Orders", Value: 4 }] }));
  await cw.send(
    new PutMetricAlarmCommand({
      AlarmName: alarm,
      Namespace: namespace,
      MetricName: "Orders",
      Statistic: "Sum",
      Period: 60,
      EvaluationPeriods: 1,
      Threshold: 100,
      ComparisonOperator: "GreaterThanThreshold",
    }),
  );

  await page.goto(`/metrics?ns=${namespace}`);
  await page.getByRole("link", { name: "Orders" }).click();
  await expect(page.getByRole("img", { name: "Metric chart" })).toBeVisible();
  await page.getByText("Datapoints").click();
  await expect(page.getByRole("table", { name: "Datapoints" })).toContainText("7");

  await page.goto("/alarms");
  await expect(row(page, alarm)).toContainText("Sum(Orders) > 100");
  await row(page, alarm).getByRole("button", { name: `Set ${alarm} to ALARM` }).click();
  await expect(row(page, alarm).locator(".status.bad")).toBeVisible();
});
