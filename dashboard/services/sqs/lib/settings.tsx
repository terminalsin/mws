"use client";

// The queue settings the create and edit forms share: dead-letter queue,
// redrive allow policy, encryption and the FIFO options. What applies
// follows the choices (a KMS key only with SSE-KMS, sources only for
// "by queue").

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { useState } from "react";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

export interface Current {
  dlq?: string;
  maxReceiveCount?: number;
  allow?: string;
  allowSources?: string[];
  encryption?: "none" | "sqs" | "kms";
  kmsKey?: string;
  kmsReuse?: string;
  dedup?: boolean;
  dedupScope?: string;
  throughput?: string;
}

export function QueueSettings({
  queues,
  current,
  fifo: fixedFifo,
  rules,
}: {
  /** Queues that can be the dead-letter queue: name and ARN. */
  queues: { name: string; arn: string; fifo: boolean }[];
  current?: Current;
  /** Known when editing; on create the FIFO box decides. */
  fifo?: boolean;
  rules: Record<"maxReceives" | "kmsKey" | "kmsReuse" | "sources", Rule>;
}) {
  const [fifoBox, setFifo] = useState(false);
  const fifo = fixedFifo ?? fifoBox;
  const [dlq, setDlq] = useState(current?.dlq ?? "");
  const [allow, setAllow] = useState(current?.allow ?? "");
  const [encryption, setEncryption] = useState(current?.encryption ?? "sqs");
  // A FIFO queue's dead-letter queue is FIFO too, and a standard one's standard.
  const candidates = queues.filter((q) => q.fifo === fifo);
  return (
    <>
      {fixedFifo === undefined && (
        <label className="check">
          <input type="checkbox" name="fifo" checked={fifoBox} onChange={(e) => setFifo(e.target.checked)} /> FIFO
        </label>
      )}
      {fifo && (
        <>
          <label className="check">
            <input type="checkbox" name="dedup" defaultChecked={current?.dedup} /> Content-based deduplication
          </label>
          <div className="form-row">
            <FieldShell label="Deduplication scope">
              <select name="dedupScope" defaultValue={current?.dedupScope ?? "queue"}>
                <option value="queue">Queue</option>
                <option value="messageGroup">Message group</option>
              </select>
            </FieldShell>
            <FieldShell label="Throughput limit">
              <select name="throughput" defaultValue={current?.throughput ?? "perQueue"}>
                <option value="perQueue">Per queue</option>
                <option value="perMessageGroupId">Per message group</option>
              </select>
            </FieldShell>
          </div>
        </>
      )}
      <div className="form-row">
        <FieldShell label="Dead-letter queue">
          <select name="dlq" value={dlq} onChange={(e) => setDlq(e.target.value)}>
            <option value="">None</option>
            {candidates.map((q) => (
              <option key={q.arn} value={q.arn}>
                {q.name}
              </option>
            ))}
            {dlq && !candidates.some((q) => q.arn === dlq) && <option value={dlq}>{dlq}</option>}
          </select>
        </FieldShell>
        {dlq && (
          <FieldShell label="Maximum receives" rule={rules.maxReceives}>
            <input name="maxReceiveCount" inputMode="numeric" defaultValue={current?.maxReceiveCount ?? 5} />
          </FieldShell>
        )}
      </div>
      <FieldShell label="Redrive allow policy">
        <select name="allow" value={allow} onChange={(e) => setAllow(e.target.value)}>
          {!current?.allow && <option value="">Default (any queue)</option>}
          <option value="allowAll">Any queue may use this as its dead-letter queue</option>
          <option value="byQueue">Only these queues</option>
          <option value="denyAll">No queue</option>
        </select>
      </FieldShell>
      {allow === "byQueue" && (
        <FieldShell label="Source queues" rule={rules.sources} known={queues.map((q) => q.arn)}>
          <textarea name="allowSources" rows={2} defaultValue={current?.allowSources?.join("\n")} spellCheck={false} />
        </FieldShell>
      )}
      <div className="form-row">
        <FieldShell label="Encryption">
          <select name="encryption" value={encryption} onChange={(e) => setEncryption(e.target.value as Current["encryption"] & string)}>
            <option value="sqs">SSE-SQS</option>
            <option value="kms">SSE-KMS</option>
            <option value="none">None</option>
          </select>
        </FieldShell>
        {encryption === "kms" && (
          <>
            <FieldShell label="KMS key" rule={rules.kmsKey} member="KmsMasterKeyId">
              <ResourcePicker kind="kms-key" name="kmsKey" required defaultValue={current?.kmsKey ?? "alias/aws/sqs"} />
            </FieldShell>
            <FieldShell label="Data key reuse (s)" rule={rules.kmsReuse} member="KmsDataKeyReusePeriodSeconds">
              <input name="kmsReuse" inputMode="numeric" defaultValue={current?.kmsReuse ?? "300"} />
            </FieldShell>
          </>
        )}
      </div>
    </>
  );
}
