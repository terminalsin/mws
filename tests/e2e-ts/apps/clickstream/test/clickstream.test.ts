import { DescribeDeliveryStreamCommand } from "@aws-sdk/client-firehose";
import { GetObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import { randomBytes } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { firehose, s3 } from "../src/clients.js";
import { pageViewsBySession, readAllClicks } from "../src/consumer.js";
import type { ClickEvent } from "../src/events.js";
import { provisionClickstream, type Clickstream } from "../src/infrastructure.js";
import { publishClicks } from "../src/producer.js";

let pipeline: Clickstream;
const clicks: ClickEvent[] = [];

beforeAll(async () => {
  pipeline = await provisionClickstream(`clicks-${randomBytes(4).toString("hex")}`);
  for (let i = 0; i < 30; i++) {
    clicks.push({
      sessionId: `s-${i % 5}`,
      userId: `u-${i % 5}`,
      page: ["/", "/products", "/cart", "/checkout"][i % 4]!,
      at: new Date(Date.UTC(2026, 10, 4, 12, 0, i)).toISOString(),
    });
  }
  await publishClicks(pipeline.streamName, clicks);
});

/**
 * Firehose flushes its buffer after BufferingHints.IntervalInSeconds. MWS
 * runs that timer on its emulated clock, which a test can move forward
 * instead of sleeping for a minute. The clock is shared by everything in
 * MWS, so put it back afterwards: other suites stamp data with the wall
 * clock and would otherwise see it as minutes old.
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

let originalOffset = 0;

beforeAll(async () => {
  originalOffset = (await clock()).offsetSeconds;
});

afterAll(async () => {
  await clock({ offsetSeconds: originalOffset });
});

describe("clickstream", () => {
  it("keeps each session on one shard, in order", async () => {
    const shards = await readAllClicks(pipeline.streamName);
    expect(shards.flatMap((s) => s.clicks)).toHaveLength(30);
    for (const { clicks: shardClicks } of shards) {
      for (const session of new Set(shardClicks.map((c) => c.sessionId))) {
        const inShard = shardClicks.filter((c) => c.sessionId === session);
        // Every click of the session is here, in the order it was sent.
        expect(inShard).toEqual(clicks.filter((c) => c.sessionId === session));
      }
    }
    expect(pageViewsBySession(shards.flatMap((s) => s.clicks))).toEqual({
      "s-0": 6,
      "s-1": 6,
      "s-2": 6,
      "s-3": 6,
      "s-4": 6,
    });
  });

  it("lands the stream in S3 as gzipped, date-partitioned batches", async () => {
    // Firehose reads the Kinesis stream about once a second, and the buffer
    // interval starts when it does. Move the clock past the interval until
    // the batch shows up (usually once, or twice if Firehose hadn't read the
    // records yet).
    const keys: string[] = [];
    for (let attempt = 0; attempt < 5 && keys.length === 0; attempt++) {
      await clock({ advanceSeconds: 61 });
      for (let i = 0; i < 10 && keys.length === 0; i++) {
        // Any Firehose call lets it notice the moved clock.
        await firehose.send(new DescribeDeliveryStreamCommand({ DeliveryStreamName: pipeline.deliveryStreamName }));
        await new Promise((r) => setTimeout(r, 300));
        const { Contents = [] } = await s3.send(new ListObjectsV2Command({ Bucket: pipeline.bucket, Prefix: "clicks/" }));
        keys.push(...Contents.map((o) => o.Key!));
      }
    }
    expect(keys.length).toBeGreaterThan(0);
    for (const key of keys) {
      expect(key).toMatch(/^clicks\/year=\d{4}\/month=\d\d\/day=\d\d\/.+-to-s3-\d+-\d{4}-\d\d-\d\d-\d\d-\d\d-\d\d-[0-9a-f-]+\.gz$/);
    }

    const delivered: ClickEvent[] = [];
    for (const key of keys) {
      const { Body } = await s3.send(new GetObjectCommand({ Bucket: pipeline.bucket, Key: key }));
      const text = gunzipSync(await Body!.transformToByteArray()).toString("utf8");
      delivered.push(...text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as ClickEvent));
    }
    expect(delivered).toHaveLength(30);
    expect(new Set(delivered.map((c) => c.at))).toEqual(new Set(clicks.map((c) => c.at)));
  });
});
