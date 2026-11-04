// A simple real-time consumer: reads every shard from the start of the
// stream and counts page views per session.
import { GetRecordsCommand, GetShardIteratorCommand, ListShardsCommand } from "@aws-sdk/client-kinesis";
import { kinesis } from "./clients.js";
import type { ClickEvent } from "./events.js";

export async function readAllClicks(streamName: string): Promise<{ shardId: string; clicks: ClickEvent[] }[]> {
  const { Shards = [] } = await kinesis.send(new ListShardsCommand({ StreamName: streamName }));
  const result = [];
  for (const shard of Shards) {
    let { ShardIterator } = await kinesis.send(
      new GetShardIteratorCommand({ StreamName: streamName, ShardId: shard.ShardId, ShardIteratorType: "TRIM_HORIZON" }),
    );
    const clicks: ClickEvent[] = [];
    // Stop once the consumer has caught up with the tip of the shard.
    while (ShardIterator) {
      const page = await kinesis.send(new GetRecordsCommand({ ShardIterator, Limit: 100 }));
      for (const record of page.Records ?? []) {
        clicks.push(JSON.parse(Buffer.from(record.Data!).toString("utf8")));
      }
      if (page.MillisBehindLatest === 0 && (page.Records ?? []).length === 0) break;
      ShardIterator = page.NextShardIterator;
    }
    result.push({ shardId: shard.ShardId!, clicks });
  }
  return result;
}

export function pageViewsBySession(clicks: ClickEvent[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const click of clicks) counts[click.sessionId] = (counts[click.sessionId] ?? 0) + 1;
  return counts;
}
