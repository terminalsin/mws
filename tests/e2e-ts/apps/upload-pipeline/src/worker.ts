// The indexer: a long-polling SQS consumer that reads S3 event notifications
// (delivered raw by SNS), builds a small index document for every new text
// upload and stores it next to the original under index/.
import { GetObjectCommand, PutObjectCommand } from "@aws-sdk/client-s3";
import { DeleteMessageCommand, ReceiveMessageCommand } from "@aws-sdk/client-sqs";
import { createHash } from "node:crypto";
import { s3, sqs } from "./clients.js";

export interface IndexEntry {
  key: string;
  size: number;
  sha256: string;
  words: number;
  lines: number;
}

interface S3EventRecord {
  eventName: string;
  s3: { bucket: { name: string }; object: { key: string; size: number } };
}

type S3Notification = { Records?: S3EventRecord[]; Event?: string };

export interface BatchResult {
  indexed: IndexEntry[];
  skipped: number;
  failed: number;
}

export async function indexDocument(bucket: string, key: string): Promise<IndexEntry> {
  const object = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  if (!object.ContentType?.startsWith("text/")) {
    throw new Error(`cannot index ${object.ContentType ?? "unknown"} content`);
  }
  const text = await object.Body!.transformToString();
  const entry: IndexEntry = {
    key,
    size: Buffer.byteLength(text),
    sha256: createHash("sha256").update(text).digest("hex"),
    words: text.split(/\s+/).filter(Boolean).length,
    lines: text.split("\n").length,
  };
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key.replace(/^uploads\//, "index/") + ".json",
      Body: JSON.stringify(entry),
      ContentType: "application/json",
    }),
  );
  return entry;
}

/** Receives one batch, indexes what it can and deletes what it handled. */
export async function processBatch(queueUrl: string, options: { waitSeconds?: number; visibilityTimeout?: number } = {}): Promise<BatchResult> {
  const result: BatchResult = { indexed: [], skipped: 0, failed: 0 };
  const { Messages = [] } = await sqs.send(
    new ReceiveMessageCommand({
      QueueUrl: queueUrl,
      MaxNumberOfMessages: 10,
      WaitTimeSeconds: options.waitSeconds ?? 1,
      VisibilityTimeout: options.visibilityTimeout,
    }),
  );
  for (const message of Messages) {
    const notification = JSON.parse(message.Body!) as S3Notification;
    try {
      // S3 sends an s3:TestEvent when notifications are configured; it has
      // no Records and is safe to drop.
      if (notification.Event === "s3:TestEvent") {
        result.skipped++;
      } else {
        for (const record of notification.Records ?? []) {
          // Keys in S3 events are URL-encoded, with '+' for spaces.
          const key = decodeURIComponent(record.s3.object.key.replace(/\+/g, " "));
          result.indexed.push(await indexDocument(record.s3.bucket.name, key));
        }
      }
      await sqs.send(new DeleteMessageCommand({ QueueUrl: queueUrl, ReceiptHandle: message.ReceiptHandle! }));
    } catch {
      // Leave the message alone: it becomes visible again after the
      // visibility timeout, and the redrive policy moves it to the DLQ once
      // it has been received maxReceiveCount times.
      result.failed++;
    }
  }
  return result;
}
