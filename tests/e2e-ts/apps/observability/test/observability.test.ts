import { DescribeAlarmsCommand, GetMetricDataCommand, GetMetricStatisticsCommand } from "@aws-sdk/client-cloudwatch";
import { FilterLogEventsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { ReceiveMessageCommand } from "@aws-sdk/client-sqs";
import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { cloudwatch, logs, sqs } from "../src/clients.js";
import { CloudWatchLogger } from "../src/logger.js";
import { Metrics } from "../src/metrics.js";
import { provisionMonitoring, type Monitoring } from "../src/monitoring.js";

const name = `obs-${randomBytes(4).toString("hex")}`;
let monitoring: Monitoring;
let logger: CloudWatchLogger;

beforeAll(async () => {
  monitoring = await provisionMonitoring(name);
  logger = new CloudWatchLogger(logs, monitoring.logGroupName, `web-${process.pid}`, { service: "checkout" });
});

/**
 * Alarms evaluate completed periods, about once a minute. MWS runs that on
 * its emulated clock, which the alarm test moves past the minute of its
 * data instead of waiting for it, and puts back afterwards (the clock is
 * shared by every suite).
 */
async function clock(body?: object): Promise<{ offsetSeconds: number }> {
  const res = await fetch(new URL("/_mws/clock", process.env.AWS_ENDPOINT_URL), {
    method: body ? "POST" : "GET",
    headers: { "content-type": "application/json" },
    body: body && JSON.stringify(body),
  });
  expect(res.ok).toBe(true);
  return res.json() as Promise<{ offsetSeconds: number }>;
}

async function eventually<T>(fn: () => Promise<T | undefined>, timeoutMs = 30_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await fn();
    if (value !== undefined) return value;
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 250));
  }
}

describe("observability", () => {
  it("ships structured logs that can be searched with filter patterns", async () => {
    logger.info("cart loaded", { cartId: "c-1", items: 3 });
    logger.info("payment authorized", { cartId: "c-1", amount: 42 });
    logger.error("payment declined", { cartId: "c-2", reason: "insufficient_funds" });
    await logger.flush();

    const { events = [] } = await logs.send(
      new FilterLogEventsCommand({ logGroupName: monitoring.logGroupName, filterPattern: '{ $.cartId = "c-1" }' }),
    );
    expect(events.map((e) => JSON.parse(e.message!).message)).toEqual(["cart loaded", "payment authorized"]);
  });

  it("publishes custom latency metrics and reads back statistics", async () => {
    const metrics = new Metrics(cloudwatch, monitoring.namespace, { Route: "/checkout" });
    for (const ms of [120, 80, 200, 100]) metrics.timing("Latency", ms);
    await metrics.flush();

    const now = Date.now();
    const { Datapoints = [] } = await cloudwatch.send(
      new GetMetricStatisticsCommand({
        Namespace: monitoring.namespace,
        MetricName: "Latency",
        Dimensions: [{ Name: "Route", Value: "/checkout" }],
        StartTime: new Date(now - 10 * 60_000),
        EndTime: new Date(now + 60_000),
        Period: 3600,
        Statistics: ["Average", "Maximum", "SampleCount"],
        Unit: "Milliseconds",
      }),
    );
    expect(Datapoints).toHaveLength(1);
    expect(Datapoints[0]).toMatchObject({ Average: 125, Maximum: 200, SampleCount: 4, Unit: "Milliseconds" });

    const { MetricDataResults = [] } = await cloudwatch.send(
      new GetMetricDataCommand({
        StartTime: new Date(now - 10 * 60_000),
        EndTime: new Date(now + 60_000),
        MetricDataQueries: [
          {
            Id: "p",
            MetricStat: {
              Metric: {
                Namespace: monitoring.namespace,
                MetricName: "Latency",
                Dimensions: [{ Name: "Route", Value: "/checkout" }],
              },
              Period: 3600,
              Stat: "Maximum",
            },
          },
          { Id: "seconds", Expression: "p / 1000" },
        ],
      }),
    );
    expect(MetricDataResults.find((r) => r.Id === "seconds")?.Values).toEqual([0.2]);
  });

  it("raises the error alarm and pages through SNS", async () => {
    for (let i = 0; i < 4; i++) logger.error("upstream timeout", { dependency: "payments" });
    await logger.flush();

    // The metric filter turned each ERROR line into a data point.
    const errors = await eventually(async () => {
      const now = Date.now();
      const { Datapoints = [] } = await cloudwatch.send(
        new GetMetricStatisticsCommand({
          Namespace: monitoring.namespace,
          MetricName: "Errors",
          StartTime: new Date(now - 10 * 60_000),
          EndTime: new Date(now + 60_000),
          Period: 3600,
          Statistics: ["Sum"],
        }),
      );
      return Datapoints[0]?.Sum !== undefined && Datapoints[0].Sum >= 5 ? Datapoints[0].Sum : undefined;
    });
    expect(errors).toBe(5);

    const { offsetSeconds } = await clock();
    await clock({ advanceSeconds: 61 });
    const alarm = await eventually(async () => {
      const { MetricAlarms = [] } = await cloudwatch.send(new DescribeAlarmsCommand({ AlarmNames: [monitoring.alarmName] }));
      return MetricAlarms[0]?.StateValue === "ALARM" ? MetricAlarms[0] : undefined;
    }, 90_000).finally(() => clock({ offsetSeconds }));
    expect(alarm.StateReason).toMatch(/Threshold Crossed/);

    const page = await eventually(async () => {
      const { Messages = [] } = await sqs.send(
        new ReceiveMessageCommand({ QueueUrl: monitoring.pagerQueueUrl, WaitTimeSeconds: 1 }),
      );
      return Messages[0];
    });
    expect(JSON.parse(page.Body!)).toMatchObject({
      AlarmName: monitoring.alarmName,
      NewStateValue: "ALARM",
      OldStateValue: expect.any(String),
      Trigger: { MetricName: "Errors", Namespace: monitoring.namespace, Threshold: 3 },
    });
  }, 120_000);
});
