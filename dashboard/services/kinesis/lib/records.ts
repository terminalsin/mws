import "server-only";

import {
  GetRecordsCommand,
  GetShardIteratorCommand,
  type _Record,
  type Shard,
  type ShardIteratorType,
} from "@aws-sdk/client-kinesis";
import { describeError, mws } from "@mws-dashboard/aws";
import { gunzipSync } from "node:zlib";

import { kinesis } from "./clients";

export type Rec = _Record & { shard: string };

/** MWS's emulated clock (arrival timestamps follow it). */
export async function clockNow(): Promise<number> {
  try {
    return new Date((await mws<{ now: string }>("/_mws/clock")).now).getTime();
  } catch {
    return Date.now();
  }
}

const bySequence = (a: Rec, b: Rec) => {
  const x = BigInt(a.SequenceNumber ?? "0");
  const y = BigInt(b.SequenceNumber ?? "0");
  return x < y ? -1 : x > y ? 1 : 0;
};

/** A record's payload as text: gzip (a CloudWatch Logs subscription) is
 * unpacked, and bytes that are not UTF-8 are shown as base64. */
export function decode(data: Uint8Array | undefined): {
  text: string;
  kind?: "gzip" | "base64";
} {
  let bytes = data ?? new Uint8Array();
  let kind: "gzip" | undefined;
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    try {
      bytes = gunzipSync(bytes);
      kind = "gzip";
    } catch {
      // not gzip after all
    }
  }
  try {
    return {
      text: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      kind,
    };
  } catch {
    return { text: Buffer.from(bytes).toString("base64"), kind: "base64" };
  }
}

/** Every record of a shard from `iterator` to the tip, keeping the newest
 * `keep` (at most `calls` GetRecords calls). */
async function tail(
  stream: string,
  shard: string,
  type: ShardIteratorType,
  timestamp: Date | undefined,
  keep: number,
  calls = 20,
) {
  const c = await kinesis();
  let it = (
    await c.send(
      new GetShardIteratorCommand({
        StreamName: stream,
        ShardId: shard,
        ShardIteratorType: type,
        Timestamp: timestamp,
      }),
    )
  ).ShardIterator;
  let out: Rec[] = [];
  let complete = false;
  for (let i = 0; i < calls && it; i++) {
    const r = await c.send(
      new GetRecordsCommand({ ShardIterator: it, Limit: 10_000 }),
    );
    out = out.concat((r.Records ?? []).map((x) => ({ ...x, shard })));
    if (out.length > keep) out = out.slice(-keep);
    it = r.NextShardIterator;
    if (!r.Records?.length && (r.MillisBehindLatest ?? 0) === 0) {
      complete = true;
      break;
    }
  }
  return { records: out, complete: complete || !it };
}

/** The newest `limit` records across shards (closed parents included, while
 * their records are retained): each shard is read from a recent timestamp,
 * widening back to the trim horizon until enough are found. Failures are
 * returned per shard, never swallowed. */
export async function newestRecords(
  stream: string,
  shards: Shard[],
  limit = 25,
) {
  const now = await clockNow();
  const errors: { shard: string; error: string }[] = [];
  let records: Rec[] = [];
  const windows: [ShardIteratorType, number | undefined][] = [
    ["AT_TIMESTAMP", 15 * 60_000],
    ["AT_TIMESTAMP", 24 * 3600_000],
    ["TRIM_HORIZON", undefined],
  ];
  for (const [type, back] of windows) {
    errors.length = 0;
    const per = await Promise.all(
      shards.map(async (s) => {
        try {
          return (
            await tail(
              stream,
              s.ShardId!,
              type,
              back ? new Date(now - back) : undefined,
              limit,
            )
          ).records;
        } catch (e) {
          errors.push({ shard: s.ShardId!, error: describeError(e) });
          return [];
        }
      }),
    );
    records = per.flat();
    if (records.length >= limit || errors.length === shards.length) break;
  }
  // Newest first; records of one moment by their sequence (later puts have higher numbers).
  records.sort(
    (a, b) =>
      (b.ApproximateArrivalTimestamp?.getTime() ?? 0) -
        (a.ApproximateArrivalTimestamp?.getTime() ?? 0) || bySequence(b, a),
  );
  return { records: records.slice(0, limit), errors };
}

/** One page of one shard from a chosen position, with the iterator for the next. */
export async function shardPage(
  stream: string,
  shard: string,
  from: {
    type: ShardIteratorType;
    timestamp?: Date;
    sequence?: string;
    iterator?: string;
  },
  limit = 25,
) {
  const c = await kinesis();
  const it =
    from.iterator ??
    (
      await c.send(
        new GetShardIteratorCommand({
          StreamName: stream,
          ShardId: shard,
          ShardIteratorType: from.type,
          Timestamp: from.timestamp,
          StartingSequenceNumber: from.sequence,
        }),
      )
    ).ShardIterator;
  const r = await c.send(
    new GetRecordsCommand({ ShardIterator: it, Limit: limit }),
  );
  return {
    records: (r.Records ?? []).map((x) => ({ ...x, shard })),
    next: r.NextShardIterator,
    behind: r.MillisBehindLatest,
  };
}
