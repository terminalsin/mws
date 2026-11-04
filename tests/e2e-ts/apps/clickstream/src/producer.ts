// The web tier: batches click events into Kinesis. Records with the same
// partition key (the session) land on the same shard, in order.
import { PutRecordsCommand, type PutRecordsRequestEntry } from "@aws-sdk/client-kinesis";
import { kinesis } from "./clients.js";
import type { ClickEvent } from "./events.js";

export async function publishClicks(streamName: string, clicks: ClickEvent[]): Promise<void> {
  let pending: PutRecordsRequestEntry[] = clicks.map((click) => ({
    Data: Buffer.from(JSON.stringify(click) + "\n"),
    PartitionKey: click.sessionId,
  }));
  // PutRecords is not atomic: retry only the entries that failed (for
  // example with ProvisionedThroughputExceededException).
  for (let attempt = 0; pending.length > 0; attempt++) {
    if (attempt === 5) throw new Error(`${pending.length} click records could not be written`);
    const { Records = [] } = await kinesis.send(new PutRecordsCommand({ StreamName: streamName, Records: pending }));
    pending = pending.filter((_, i) => Records[i]?.ErrorCode);
    if (pending.length) await new Promise((r) => setTimeout(r, 100 * 2 ** attempt));
  }
}
