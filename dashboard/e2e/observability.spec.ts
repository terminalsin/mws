import { CloudWatchClient, PutMetricAlarmCommand, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { expect, test } from "@playwright/test";

import { rowAction, sdk, submit, unique } from "./helpers";

test("Logs: create a group, write and search events", async ({ page }) => {
  const group = `/dash/${unique("app")}`;
  await page.goto("/observability/logs");
  await submit(page, "create-log-group", { name: group });
  await page.getByRole("link", { name: group }).click();
  await submit(page, "write-event", { message: "ERROR something broke" });
  await submit(page, "write-event", { message: "INFO all good" });
  await page.reload();
  const events = page.getByRole("table", { name: "Log events" });
  await expect(events).toContainText("INFO all good");

  await page.getByLabel("Filter pattern").fill("ERROR");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(events).toContainText("ERROR something broke");
  await expect(events).not.toContainText("INFO all good");
});

test("CloudWatch: metrics chart and alarm state", async ({ page }) => {
  const namespace = unique("Dash");
  const alarm = unique("dash-alarm");
  const cw = new CloudWatchClient(sdk);
  await cw.send(
    new PutMetricDataCommand({ Namespace: namespace, MetricData: [{ MetricName: "Orders", Value: 3 }, { MetricName: "Orders", Value: 4 }] }),
  );
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

  await page.goto(`/observability/metrics?ns=${namespace}`);
  await page.getByRole("link", { name: "Orders" }).click();
  await expect(page.getByRole("img", { name: "Metric chart" })).toBeVisible();
  await expect(page.getByRole("table", { name: "Datapoints" })).toContainText("7");

  await page.goto("/observability/alarms");
  const row = await rowAction(page, alarm, "Set state");
  await expect(row.locator(".badge")).toHaveText("ALARM");
});
