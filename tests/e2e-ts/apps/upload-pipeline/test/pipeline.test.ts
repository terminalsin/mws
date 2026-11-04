import { GetObjectCommand, HeadObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import { ReceiveMessageCommand } from "@aws-sdk/client-sqs";
import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { s3, sqs } from "../src/clients.js";
import { provisionPipeline, type Pipeline } from "../src/infrastructure.js";
import { createDownloadUrl, createUploadUrl } from "../src/uploads.js";
import { processBatch, type IndexEntry } from "../src/worker.js";

let pipeline: Pipeline;

beforeAll(async () => {
  // Unique names keep runs independent without resetting the emulator.
  pipeline = await provisionPipeline(`docs-${randomBytes(4).toString("hex")}`);
  // Configuring the notification sent an s3:TestEvent to both queues.
  expect((await processBatch(pipeline.indexQueueUrl)).skipped).toBe(1);
});

async function indexUntil(predicate: (indexed: IndexEntry[]) => boolean): Promise<IndexEntry[]> {
  const indexed: IndexEntry[] = [];
  for (let i = 0; i < 10 && !predicate(indexed); i++) {
    indexed.push(...(await processBatch(pipeline.indexQueueUrl)).indexed);
  }
  return indexed;
}

describe("upload pipeline", () => {
  it("indexes a document uploaded by a browser through a presigned URL", async () => {
    const text = "Quarterly report\nRevenue grew in every region.\n";
    const ticket = await createUploadUrl(pipeline.bucket, "report q3.txt", "text/plain");

    // A plain HTTP PUT, as a browser would send it: no SDK, no credentials.
    const put = await fetch(ticket.url, { method: "PUT", headers: ticket.headers, body: text });
    expect(put.status).toBe(200);

    const indexed = await indexUntil((entries) => entries.length > 0);
    expect(indexed).toEqual([
      expect.objectContaining({ key: ticket.key, size: text.length, words: 7, lines: 3 }),
    ]);

    const indexObject = await s3.send(
      new GetObjectCommand({
        Bucket: pipeline.bucket,
        Key: ticket.key.replace("uploads/", "index/") + ".json",
      }),
    );
    expect(JSON.parse(await indexObject.Body!.transformToString())).toEqual(indexed[0]);

    const download = await fetch(await createDownloadUrl(pipeline.bucket, ticket.key));
    expect(await download.text()).toBe(text);
  });

  it("rejects an upload whose Content-Type differs from the signed one", async () => {
    const ticket = await createUploadUrl(pipeline.bucket, "notes.txt", "text/plain");
    const put = await fetch(ticket.url, {
      method: "PUT",
      headers: { "content-type": "application/octet-stream" },
      body: "hello",
    });
    expect(put.status).toBe(403);
    expect(await put.text()).toContain("<Code>SignatureDoesNotMatch</Code>");
    await expect(s3.send(new HeadObjectCommand({ Bucket: pipeline.bucket, Key: ticket.key }))).rejects.toMatchObject({
      name: "NotFound",
      $metadata: { httpStatusCode: 404 },
    });
  });

  it("only notifies for keys under the uploads/ prefix", async () => {
    await s3.send(new PutObjectCommand({ Bucket: pipeline.bucket, Key: "tmp/scratch.txt", Body: "ignored", ContentType: "text/plain" }));
    await s3.send(new PutObjectCommand({ Bucket: pipeline.bucket, Key: "uploads/direct/readme.txt", Body: "one two three", ContentType: "text/plain" }));

    const indexed = await indexUntil((entries) => entries.length > 0);
    expect(indexed.map((e) => e.key)).toEqual(["uploads/direct/readme.txt"]);
  });

  it("keeps the SNS envelope for the audit subscriber", async () => {
    await s3.send(new PutObjectCommand({ Bucket: pipeline.bucket, Key: "uploads/audit/a.txt", Body: "a", ContentType: "text/plain" }));

    const bodies: Array<{ Type: string; Subject: string; Message: string; TopicArn: string }> = [];
    for (let i = 0; i < 10; i++) {
      const { Messages = [] } = await sqs.send(
        new ReceiveMessageCommand({ QueueUrl: pipeline.auditQueueUrl, MaxNumberOfMessages: 10, WaitTimeSeconds: 1 }),
      );
      bodies.push(...Messages.map((m) => JSON.parse(m.Body!)));
      if (bodies.some((b) => b.Message.includes("uploads/audit/a.txt"))) break;
    }
    const envelope = bodies.find((b) => b.Message.includes("uploads/audit/a.txt"))!;
    expect(envelope).toMatchObject({
      Type: "Notification",
      Subject: "Amazon S3 Notification",
      TopicArn: pipeline.topicArn,
    });
    const event = JSON.parse(envelope.Message);
    expect(event.Records[0]).toMatchObject({
      eventSource: "aws:s3",
      eventName: "ObjectCreated:Put",
      s3: { bucket: { name: pipeline.bucket }, object: { key: "uploads/audit/a.txt", size: 1 } },
    });
  });

  it("moves documents it cannot index to the dead-letter queue", async () => {
    await s3.send(
      new PutObjectCommand({
        Bucket: pipeline.bucket,
        Key: "uploads/photos/cat.png",
        Body: randomBytes(64),
        ContentType: "image/png",
      }),
    );

    // Each failed attempt leaves the message on the queue; a 1 second
    // visibility timeout makes it come back quickly for the retry.
    let failures = 0;
    for (let i = 0; i < 10 && failures < 2; i++) {
      failures += (await processBatch(pipeline.indexQueueUrl, { visibilityTimeout: 1 })).failed;
    }
    expect(failures).toBe(2);

    // The third receive finds the queue empty: SQS moved the message to the DLQ.
    await new Promise((resolve) => setTimeout(resolve, 1100));
    expect(await processBatch(pipeline.indexQueueUrl)).toEqual({ indexed: [], skipped: 0, failed: 0 });

    const { Messages = [] } = await sqs.send(
      new ReceiveMessageCommand({
        QueueUrl: pipeline.deadLetterQueueUrl,
        WaitTimeSeconds: 2,
      }),
    );
    expect(Messages).toHaveLength(1);
    expect(Messages[0]!.Body).toContain("uploads/photos/cat.png");
  });
});
