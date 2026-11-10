import { CloudWatchClient, PutMetricAlarmCommand, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient, CreateLogGroupCommand } from "@aws-sdk/client-cloudwatch-logs";
import { CreateTopicCommand, SNSClient } from "@aws-sdk/client-sns";
import { expect, test, type Page } from "@playwright/test";

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

// Inline validation (packages/ui fields.tsx): problems show on the field with
// one-click repairs, and what MWS rejects lands on the field it concerns.

async function openSheet(page: Page, path: string, testId: string) {
  await page.goto(path);
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  const input = (name: string) => form.locator(`[name="${name}"]`);
  return { form, field, input };
}

test("CloudWatch: the alarm form repairs names, dimensions, topics and periods", async ({ page }) => {
  const namespace = unique("DashValid");
  const existing = unique("dash-alarm");
  const topic = unique("dash-alerts");
  const cw = new CloudWatchClient(sdk);
  await cw.send(new PutMetricDataCommand({ Namespace: namespace, MetricData: [{ MetricName: "Orders", Value: 1, Dimensions: [{ Name: "QueueName", Value: "orders" }] }] }));
  await cw.send(
    new PutMetricAlarmCommand({ AlarmName: existing, Namespace: namespace, MetricName: "Orders", Statistic: "Sum", Period: 60, EvaluationPeriods: 1, Threshold: 1, ComparisonOperator: "GreaterThanThreshold" }),
  );
  const topicArn = (await new SNSClient(sdk).send(new CreateTopicCommand({ Name: topic }))).TopicArn!;

  const { form, field, input } = await openSheet(page, "/alarms", "create-alarm");

  // A taken name offers the next free one.
  await input("name").fill(existing);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(input("name")).toHaveValue(`${existing}-2`);

  // A namespace AWS rejects suggests the known one it was meant to be.
  await input("namespace").fill(`:${namespace}`);
  await input("namespace").blur();
  await expect(field("namespace")).toHaveAttribute("data-invalid", "pattern");
  await field("namespace").getByRole("button", { name: new RegExp(`Did you mean ${namespace}`) }).click();
  await expect(input("namespace")).toHaveValue(namespace);
  await input("metric").fill("Orders");

  // Dimensions written as "Name: value" are rewritten as Name=value.
  await input("dims").fill("QueueName: orders");
  await input("dims").blur();
  await expect(field("dims")).toHaveAttribute("data-invalid", "format");
  await field("dims").getByRole("button", { name: /key=value/ }).click();
  await expect(input("dims")).toHaveValue("QueueName=orders");

  // A mistyped topic name resolves to the topic's ARN.
  await input("action").fill(topic.replace("alerts", "alrets"));
  await input("action").blur();
  await expect(field("action")).toHaveAttribute("data-invalid", "format");
  await field("action").getByRole("button", { name: new RegExp(`Did you mean ${topic}`) }).click();
  await expect(input("action")).toHaveValue(topicArn);

  // More periods than a day holds: MWS refuses, and the field offers the most it allows.
  await input("threshold").fill("5");
  await input("evaluations").fill("2000");
  await form.locator('button[type="submit"]').click();
  await expect(field("evaluations")).toHaveAttribute("data-invalid", "range");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("evaluations").getByRole("button", { name: /maximum/ }).click();
  await expect(input("evaluations")).toHaveValue("1440");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, `${existing}-2`)).toContainText("1440/1440");
});

test("Logs: log group and stream names are repaired in place", async ({ page }) => {
  const base = unique("dash-valid");
  const later = `/dash/${unique("later")}`;

  let { form, field, input } = await openSheet(page, "/logs", "create-log-group");
  // Spaces are not allowed in log group names.
  await input("name").fill(`/dash/${base} api`);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /Replace spaces/ }).click();
  await expect(input("name")).toHaveValue(`/dash/${base}-api`);

  // Created after the page loaded: ResourceAlreadyExists lands on the name with the next free one.
  ({ form, field, input } = await openSheet(page, "/logs", "create-log-group"));
  await new CloudWatchLogsClient(sdk).send(new CreateLogGroupCommand({ logGroupName: later }));
  await input("name").fill(later);
  await form.locator('button[type="submit"]').click();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(input("name")).toHaveValue(`${later}-2`);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByRole("link", { name: `${later}-2` })).toBeVisible();

  // Stream names cannot hold ":" or "*".
  ({ form, field, input } = await openSheet(page, `/logs/group?name=${encodeURIComponent(`${later}-2`)}`, "write-event"));
  await input("stream").fill("web:1*");
  await input("stream").blur();
  await expect(field("stream")).toHaveAttribute("data-invalid", "pattern");
  await field("stream").getByRole("button", { name: /Remove unsupported/ }).click();
  await expect(input("stream")).toHaveValue("web-1");
  await input("message").fill("hello");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
});
