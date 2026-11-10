import {
  CloudWatchClient,
  PutLogAlarmCommand,
  PutMetricAlarmCommand,
  PutMetricDataCommand,
} from "@aws-sdk/client-cloudwatch";
import {
  CloudWatchLogsClient,
  CreateLogGroupCommand,
  CreateLogStreamCommand,
  PutLogEventsCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { CreateStreamCommand, KinesisClient } from "@aws-sdk/client-kinesis";
import { CreateTopicCommand, SNSClient } from "@aws-sdk/client-sns";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

async function clock() {
  const r = await fetch(`${sdk.endpoint}/_mws/clock`);
  return new Date(((await r.json()) as { now: string }).now).getTime();
}

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
  await cw.send(
    new PutMetricDataCommand({
      Namespace: namespace,
      MetricData: [
        { MetricName: "Orders", Value: 3 },
        { MetricName: "Orders", Value: 4 },
      ],
    }),
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

  await page.goto(`/metrics?ns=${namespace}`);
  await page.getByRole("link", { name: "Orders" }).click();
  await expect(page.getByRole("img", { name: "Metric chart" })).toBeVisible();
  await page.getByText("Datapoints").click();
  await expect(page.getByRole("table", { name: "Datapoints" })).toContainText(
    "7",
  );

  await page.goto("/alarms");
  await expect(row(page, alarm)).toContainText("Sum(Orders) > 100");
  await row(page, alarm)
    .getByRole("button", { name: `Set ${alarm} to ALARM` })
    .click();
  await expect(row(page, alarm).locator(".status.bad")).toBeVisible();
});

// Inline validation (packages/ui fields.tsx): problems show on the field with
// one-click repairs, and what MWS rejects lands on the field it concerns.

async function openSheet(page: Page, path: string, testId: string) {
  await page.goto(path);
  const form = page
    .locator("dialog[open]")
    .getByTestId(testId)
    .and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible()))
      await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) =>
    form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  const input = (name: string) => form.locator(`[name="${name}"]`);
  return { form, field, input };
}

test("CloudWatch: the alarm form repairs names, dimensions, topics and periods", async ({
  page,
}) => {
  const namespace = unique("DashValid");
  const existing = unique("dash-alarm");
  const topic = unique("dash-alerts");
  const cw = new CloudWatchClient(sdk);
  await cw.send(
    new PutMetricDataCommand({
      Namespace: namespace,
      MetricData: [
        {
          MetricName: "Orders",
          Value: 1,
          Dimensions: [{ Name: "QueueName", Value: "orders" }],
        },
      ],
    }),
  );
  await cw.send(
    new PutMetricAlarmCommand({
      AlarmName: existing,
      Namespace: namespace,
      MetricName: "Orders",
      Statistic: "Sum",
      Period: 60,
      EvaluationPeriods: 1,
      Threshold: 1,
      ComparisonOperator: "GreaterThanThreshold",
    }),
  );
  const topicArn = (
    await new SNSClient(sdk).send(new CreateTopicCommand({ Name: topic }))
  ).TopicArn!;

  const { form, field, input } = await openSheet(
    page,
    "/alarms",
    "create-alarm",
  );

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
  await field("namespace")
    .getByRole("button", { name: new RegExp(`Did you mean ${namespace}`) })
    .click();
  await expect(input("namespace")).toHaveValue(namespace);
  await input("metric").fill("Orders");

  // Dimensions written as "Name: value" are rewritten as Name=value.
  await input("dims").fill("QueueName: orders");
  await input("dims").blur();
  await expect(field("dims")).toHaveAttribute("data-invalid", "format");
  await field("dims")
    .getByRole("button", { name: /key=value/ })
    .click();
  await expect(input("dims")).toHaveValue("QueueName=orders");

  // A mistyped topic name resolves to the topic's ARN.
  await input("action").fill(topic.replace("alerts", "alrets"));
  await input("action").blur();
  await expect(field("action")).toHaveAttribute("data-invalid", "format");
  await field("action")
    .getByRole("button", { name: new RegExp(`Did you mean ${topic}`) })
    .click();
  await expect(input("action")).toHaveValue(topicArn);

  // More periods than a day holds: MWS refuses, and the field offers the most it allows.
  await input("threshold").fill("5");
  await input("evaluations").fill("2000");
  await form.locator('button[type="submit"]').click();
  await expect(field("evaluations")).toHaveAttribute("data-invalid", "range");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("evaluations")
    .getByRole("button", { name: /maximum/ })
    .click();
  await expect(input("evaluations")).toHaveValue("1440");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, `${existing}-2`)).toContainText("1440/1440");
});

test("Logs: log group and stream names are repaired in place", async ({
  page,
}) => {
  const base = unique("dash-valid");
  const later = `/dash/${unique("later")}`;

  let { form, field, input } = await openSheet(
    page,
    "/logs",
    "create-log-group",
  );
  // Spaces are not allowed in log group names.
  await input("name").fill(`/dash/${base} api`);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name")
    .getByRole("button", { name: /Replace spaces/ })
    .click();
  await expect(input("name")).toHaveValue(`/dash/${base}-api`);

  // Created after the page loaded: ResourceAlreadyExists lands on the name with the next free one.
  ({ form, field, input } = await openSheet(page, "/logs", "create-log-group"));
  await new CloudWatchLogsClient(sdk).send(
    new CreateLogGroupCommand({ logGroupName: later }),
  );
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
  ({ form, field, input } = await openSheet(
    page,
    `/logs/group?name=${encodeURIComponent(`${later}-2`)}`,
    "write-event",
  ));
  await input("stream").fill("web:1*");
  await input("stream").blur();
  await expect(field("stream")).toHaveAttribute("data-invalid", "pattern");
  await field("stream")
    .getByRole("button", { name: /Remove unsupported/ })
    .click();
  await expect(input("stream")).toHaveValue("web-1");
  await input("message").fill("hello");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
});

test("CloudWatch: alarm detail shows actions and history, and edits in place", async ({
  page,
}) => {
  const namespace = unique("DashDetail");
  const alarm = unique("dash-detail");
  const topic = unique("dash-detail-topic");
  const cw = new CloudWatchClient(sdk);
  await cw.send(
    new PutMetricDataCommand({
      Namespace: namespace,
      MetricData: [{ MetricName: "Latency", Value: 10 }],
    }),
  );
  const topicArn = (
    await new SNSClient(sdk).send(new CreateTopicCommand({ Name: topic }))
  ).TopicArn!;
  await cw.send(
    new PutMetricAlarmCommand({
      AlarmName: alarm,
      AlarmDescription: "p99 too slow",
      Namespace: namespace,
      MetricName: "Latency",
      Statistic: "Average",
      Period: 60,
      EvaluationPeriods: 1,
      Threshold: 500,
      ComparisonOperator: "GreaterThanThreshold",
      AlarmActions: [topicArn],
    }),
  );

  await page.goto("/alarms");
  await row(page, alarm).getByRole("link").first().click();
  await expect(
    page.getByRole("heading", { level: 1, name: alarm }),
  ).toBeVisible();
  await expect(page.locator(".facts")).toContainText("p99 too slow");
  await expect(page.locator(".facts")).toContainText("Average(Latency) > 500");

  await page.getByRole("link", { name: /^Actions/ }).click();
  await expect(
    page
      .getByRole("list", { name: "In alarm actions" })
      .getByRole("link", { name: new RegExp(topic) }),
  ).toHaveAttribute("href", `/sns/topic?arn=${encodeURIComponent(topicArn)}`);

  await submit(page, "set-state", {
    state: "ALARM",
    reason: "testing from the console",
  });
  await page.getByRole("link", { name: "History" }).click();
  await expect(page.getByRole("list", { name: "Alarm history" })).toContainText(
    "testing from the console",
  );

  await submit(page, "edit-alarm", { threshold: "750", ok: topicArn });
  await page.getByRole("link", { name: "Details" }).click();
  await expect(page.locator(".facts")).toContainText("Average(Latency) > 750");
});

test("CloudWatch: log and composite alarms are listed and counted", async ({
  page,
}) => {
  const child = unique("dash-child");
  const logAlarm = unique("dash-logalarm");
  const composite = unique("dash-composite");
  const cw = new CloudWatchClient(sdk);
  await cw.send(
    new PutMetricAlarmCommand({
      AlarmName: child,
      Namespace: unique("DashChild"),
      MetricName: "Errors",
      Statistic: "Sum",
      Period: 60,
      EvaluationPeriods: 1,
      Threshold: 1,
      ComparisonOperator: "GreaterThanThreshold",
    }),
  );
  await cw.send(
    new PutLogAlarmCommand({
      AlarmName: logAlarm,
      ScheduledQueryConfiguration: {
        QueryString:
          "fields @message | filter @message like /ERROR/ | stats count(*) as errors",
        LogGroupIdentifiers: ["/dash/app"],
        ScheduledQueryRoleARN: "arn:aws:iam::000000000000:role/dash-query",
        ScheduleConfiguration: {
          ScheduleExpression: "rate(5 minutes)",
          StartTimeOffset: 300,
        },
        AggregationExpression: "errors",
      },
      QueryResultsToEvaluate: 1,
      QueryResultsToAlarm: 1,
      Threshold: 0,
      ComparisonOperator: "GreaterThanThreshold",
    }),
  );
  await page.goto("/alarms");
  await expect(row(page, logAlarm)).toContainText("Logs");

  await submit(page, "create-composite", {
    name: composite,
    rule: `ALARM("${child}")`,
  });
  await expect(
    page.getByRole("heading", { level: 1, name: composite }),
  ).toBeVisible();
  await expect(page.getByRole("list", { name: "Child alarms" })).toContainText(
    child,
  );
  await page.goto(
    `/alarms/alarm?name=${encodeURIComponent(child)}&tab=parents`,
  );
  await expect(page.getByRole("list", { name: "Parent alarms" })).toContainText(
    composite,
  );
});

test("CloudWatch: dashboards are created, drawn and edited", async ({
  page,
}) => {
  const namespace = unique("DashBoard");
  const name = unique("dash-board");
  await new CloudWatchClient(sdk).send(
    new PutMetricDataCommand({
      Namespace: namespace,
      MetricData: [{ MetricName: "Orders", Value: 5 }],
    }),
  );
  await page.goto("/dashboards");
  await submit(page, "create-dashboard", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.getByTestId("widget")).toContainText("# My dashboard");

  await submit(page, "add-metric-widget", {
    title: "Orders",
    namespace,
    metric: "Orders",
    stat: "Sum",
    period: "60",
  });
  await expect(page.getByRole("img", { name: "Orders" })).toBeVisible();
  await expect(page.getByRole("img", { name: "Orders" })).toHaveAttribute(
    "src",
    /^data:image\/png;base64,/,
  );

  await submit(page, "add-text-widget", {
    markdown: "Runbook: restart the worker",
  });
  await expect(page.getByTestId("widget")).toHaveCount(3);
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByRole("button", { name: "Remove Orders" }).click();
  await expect(page.getByTestId("widget")).toHaveCount(2);

  await page.goto("/dashboards");
  await expect(row(page, name)).toBeVisible();
});

test("CloudWatch: publish datapoints and switch statistics", async ({
  page,
}) => {
  const namespace = unique("DashPut");
  await new CloudWatchClient(sdk).send(
    new PutMetricDataCommand({
      Namespace: namespace,
      MetricData: [{ MetricName: "Jobs", Value: 1 }],
    }),
  );
  await page.goto(`/metrics?ns=${namespace}&metric=Jobs&dims=[]`);
  await submit(page, "put-metric-data", {
    namespace,
    metric: "Jobs",
    value: "9",
    count: "2",
  });
  await page.getByRole("link", { name: "Maximum", exact: true }).click();
  await expect(page).toHaveURL(/stat=Maximum/);
  await expect(page.getByRole("img", { name: "Metric chart" })).toBeVisible();
  await page.getByText("Datapoints", { exact: true }).click();
  // 2 × 9 published now, plus the seeded 1 when both land in the same minute.
  await expect(page.getByRole("table", { name: "Datapoints" })).toContainText(
    /18|19/,
  );
});

test("Logs: newest events first, older ones a page away", async ({ page }) => {
  const group = `/dash/${unique("busy")}`;
  const logs = new CloudWatchLogsClient(sdk);
  await logs.send(new CreateLogGroupCommand({ logGroupName: group }));
  await logs.send(
    new CreateLogStreamCommand({ logGroupName: group, logStreamName: "web" }),
  );
  const now = await clock();
  // 260 events a second apart, oldest first: more than one page.
  const events = Array.from({ length: 260 }, (_, i) => ({
    timestamp: now - (260 - i) * 1000,
    message: `event ${String(i).padStart(3, "0")}`,
  }));
  await logs.send(
    new PutLogEventsCommand({
      logGroupName: group,
      logStreamName: "web",
      logEvents: events,
    }),
  );

  await page.goto(`/logs/group?name=${encodeURIComponent(group)}`);
  const list = page.getByRole("list", { name: "Log events" });
  await expect(list.locator("li").first()).toContainText("event 259");
  await expect(list).not.toContainText("event 010");
  await page.getByTestId("load-more").click();
  await expect(list.locator("li").first()).toContainText("event 059");
  await expect(list).toContainText("event 000");

  await page.getByTestId("live-tail").click();
  await expect(page).toHaveURL(/live=1/);
});

test("Logs: metric and subscription filters, and an Insights query", async ({
  page,
}) => {
  const group = `/dash/${unique("filters")}`;
  const stream = unique("dash-sub");
  const logs = new CloudWatchLogsClient(sdk);
  await logs.send(new CreateLogGroupCommand({ logGroupName: group }));
  await new KinesisClient(sdk).send(
    new CreateStreamCommand({ StreamName: stream, ShardCount: 1 }),
  );
  await logs.send(
    new CreateLogStreamCommand({ logGroupName: group, logStreamName: "app" }),
  );
  await logs.send(
    new PutLogEventsCommand({
      logGroupName: group,
      logStreamName: "app",
      logEvents: [
        { timestamp: await clock(), message: "ERROR payment declined" },
      ],
    }),
  );

  await page.goto(
    `/logs/group?name=${encodeURIComponent(group)}&tab=metric-filters`,
  );
  await submit(page, "create-metric-filter", {
    name: "errors",
    pattern: "ERROR",
    namespace: "DashApp",
    metric: "Errors",
  });
  await expect(row(page, "errors")).toContainText("DashApp/Errors");
  const result = await submit(page, "test-metric-filter", {
    pattern: "ERROR",
    samples: "ERROR one\nINFO two",
  });
  await expect(result).toContainText("1 of 2 match");
  await page.keyboard.press("Escape");

  await page.goto(
    `/logs/group?name=${encodeURIComponent(group)}&tab=subscriptions`,
  );
  const sheet = page
    .locator("dialog[open]")
    .getByTestId("create-subscription")
    .and(page.locator("form"));
  await expect(async () => {
    if (!(await sheet.isVisible()))
      await page.getByTestId("create-subscription-open").click();
    await expect(sheet).toBeVisible({ timeout: 1000 });
  }).toPass();
  await sheet.locator('[name="name"]').fill("to-kinesis");
  await sheet
    .getByTestId("subscription-role")
    .getByRole("button", { name: "Create automatically" })
    .click();
  // The account id: whatever the console's own account is (the datalist knows it).
  const known = await sheet
    .locator("#subscription-targets option")
    .evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value));
  const arn = known.find((v) => v.endsWith(`:stream/${stream}`));
  expect(arn).toBeTruthy();
  await sheet.locator('[name="destination"]').fill(arn!);
  await sheet.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, "to-kinesis").getByRole("link")).toHaveAttribute(
    "href",
    `/kinesis/stream?name=${stream}`,
  );

  await page.goto(`/logs/insights?groups=${encodeURIComponent(group)}`);
  // Submitted once the page has hydrated (the action redirects to the query's results).
  await expect(async () => {
    await page
      .locator('[data-testid="run-query"] [name="query"]')
      .fill("fields @timestamp, @message | filter @message like /payment/");
    await page
      .locator('[data-testid="run-query"] button[type="submit"]')
      .click();
    await expect(page).toHaveURL(/[?&]id=/, { timeout: 3000 });
  }).toPass();
  await expect(
    page.getByRole("table", { name: "Query results" }),
  ).toContainText("ERROR payment declined");
});
