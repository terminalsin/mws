"use client";

// The Add trigger sheet's fields: what applies follows the source (a
// stream has a starting position, a queue doesn't).

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { useState } from "react";

const SOURCE_ICONS: Record<string, string> = {
  sqs: "resource/AmazonSimpleQueueServiceQueue",
  kinesis: "service/AmazonKinesisDataStreams",
  dynamodb: "service/AmazonDynamoDB",
  kafka: "service/AmazonManagedStreamingforApacheKafka",
  mq: "service/AmazonMQ",
};

/** Existing queues and streams as tiles; the ARN field stays for anything else. */
const tiles = (sources: string[]) =>
  sources.slice(0, 12).map((s) => {
    const svc = s.split(":")[2] ?? "";
    return { id: s, label: s.split(/[:/]/).pop() ?? s, title: s, icon: SOURCE_ICONS[svc] ?? "service/AWSLambda" };
  });

export function TriggerFields({ sources, rules, arn }: { sources: string[]; rules: Record<"source" | "batch" | "window" | "filter", Rule>; arn: string }) {
  const [source, setSource] = useState(sources[0] ?? "");
  const stream = source.split(":")[2] === "kinesis";
  return (
    <>
      {sources.length > 0 && <PresetGallery presets={tiles(sources)} chosen={source} choose={(t) => setSource(t.id)} label="Source" testId="trigger-source" />}
      <FieldShell label="Source" rule={rules.source} known={sources} arn={arn} member="EventSourceArn">
        <input name="source" required list="trigger-sources" value={source} onChange={(e) => setSource(e.target.value)} placeholder="arn:aws:sqs:…" spellCheck={false} />
      </FieldShell>
      <datalist id="trigger-sources">
        {sources.map((s) => (
          <option key={s} value={s}>
            {s.split(":").pop()}
          </option>
        ))}
      </datalist>
      <FieldShell label="Batch size" rule={rules.batch} member="BatchSize">
        <input name="batch" inputMode="numeric" placeholder={stream ? "100" : "10"} />
      </FieldShell>
      <label className="check">
        <input type="checkbox" name="grant" defaultChecked /> Add the source permissions to the execution role
      </label>
      <MoreFields>
        <div className="form-row">
          <FieldShell label="Batch window (s)" rule={rules.window} member="MaximumBatchingWindowInSeconds">
            <input name="window" inputMode="numeric" placeholder="0" />
          </FieldShell>
          {stream && (
            <FieldShell label="Starting position">
              <select name="position" defaultValue="LATEST">
                <option>LATEST</option>
                <option>TRIM_HORIZON</option>
              </select>
            </FieldShell>
          )}
        </div>
        <FieldShell label="Filter pattern" rule={rules.filter} member="FilterCriteria">
          <textarea name="filter" rows={3} placeholder='{"body": {"type": ["order"]}}' spellCheck={false} />
        </FieldShell>
        <label className="check">
          <input type="checkbox" name="partial" /> Report batch item failures
        </label>
        <label className="check">
          <input type="checkbox" name="enabled" value="off" /> Create disabled
        </label>
      </MoreFields>
    </>
  );
}
