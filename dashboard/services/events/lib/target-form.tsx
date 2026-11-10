"use client";

// A target's fields: input shaping follows the chosen mode, and the
// parameters only some targets take (an SQS FIFO group, a Kinesis
// partition key, a role) appear for those targets.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell } from "@mws-dashboard/ui/fields";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { useState } from "react";

export interface TargetValues {
  id?: string;
  arn?: string;
  input?: string;
  inputPath?: string;
  inputPaths?: string;
  inputTemplate?: string;
  retries?: number;
  age?: number;
  dlq?: string;
  role?: string;
  group?: string;
  partitionKey?: string;
}

type Rules = Record<"id" | "arn" | "input" | "inputPath" | "inputPaths" | "inputTemplate" | "retries" | "age" | "dlq" | "role" | "group", Rule>;

export function TargetFields({ values, rules, known, ids }: { values?: TargetValues; rules: Rules; known: string[]; ids: string[] }) {
  const [arn, setArn] = useState(values?.arn ?? "");
  const initial = values?.inputTemplate ? "transformer" : values?.inputPath ? "path" : values?.input ? "constant" : "matched";
  const [mode, setMode] = useState(initial);
  const service = arn.split(":")[2];
  const fifo = service === "sqs" && arn.endsWith(".fifo");
  const needsRole = ["kinesis", "firehose", "events", "states", "ecs", "ssm"].includes(service ?? "");
  return (
    <>
      <div className="form-row">
        {values?.id ? (
          <input type="hidden" name="id" value={values.id} />
        ) : (
          <FieldShell label="Target ID" rule={rules.id} taken={ids} member="Id">
            <input name="id" required defaultValue={`target-${ids.length + 1}`} spellCheck={false} />
          </FieldShell>
        )}
        <FieldShell label="Target ARN" rule={rules.arn} known={known} member="Arn">
          <input name="target" required value={arn} onChange={(e) => setArn(e.target.value)} list="rule-targets" spellCheck={false} />
        </FieldShell>
      </div>
      <datalist id="rule-targets">
        {known.map((a) => (
          <option key={a} value={a} />
        ))}
      </datalist>
      <FieldShell label="Input">
        <select name="input" value={mode} onChange={(e) => setMode(e.target.value)}>
          <option value="matched">Matched event</option>
          <option value="path">Part of the matched event</option>
          <option value="constant">Constant (JSON text)</option>
          <option value="transformer">Input transformer</option>
        </select>
      </FieldShell>
      {mode === "constant" && (
        <FieldShell label="Constant" rule={rules.input} member="Input">
          <textarea name="inputValue" rows={3} required defaultValue={values?.input} spellCheck={false} />
        </FieldShell>
      )}
      {mode === "path" && (
        <FieldShell label="JSONPath" rule={rules.inputPath} member="InputPath">
          <input name="inputPath" required placeholder="$.detail" defaultValue={values?.inputPath} spellCheck={false} />
        </FieldShell>
      )}
      {mode === "transformer" && (
        <>
          <FieldShell label="Input paths" rule={rules.inputPaths} member="InputTransformer.InputPathsMap">
            <textarea name="inputPaths" rows={3} placeholder='{"id": "$.detail.id"}' defaultValue={values?.inputPaths} spellCheck={false} />
          </FieldShell>
          <FieldShell label="Template" rule={rules.inputTemplate} member="InputTransformer.InputTemplate">
            <textarea name="inputTemplate" rows={3} required placeholder='{"order": <id>}' defaultValue={values?.inputTemplate} spellCheck={false} />
          </FieldShell>
        </>
      )}
      <MoreFields label="Retries, dead-letter queue">
        <div className="form-row">
          <FieldShell label="Retry attempts" rule={rules.retries} member="RetryPolicy.MaximumRetryAttempts">
            <input name="retries" inputMode="numeric" placeholder="185" defaultValue={values?.retries} />
          </FieldShell>
          <FieldShell label="Maximum event age (s)" rule={rules.age} member="RetryPolicy.MaximumEventAgeInSeconds">
            <input name="age" inputMode="numeric" placeholder="86400" defaultValue={values?.age} />
          </FieldShell>
        </div>
        <FieldShell label="Dead-letter queue" rule={{ ...rules.dlq, required: false }} known={known.filter((a) => a.split(":")[2] === "sqs")} member="DeadLetterConfig.Arn">
          <input name="dlq" defaultValue={values?.dlq} spellCheck={false} />
        </FieldShell>
      </MoreFields>
      {(needsRole || values?.role) && (
        <FieldShell label="Role" rule={{ ...rules.role, required: false }} member="RoleArn">
          <input name="role" defaultValue={values?.role} spellCheck={false} />
        </FieldShell>
      )}
      {fifo && (
        <FieldShell label="Message group ID" rule={{ ...rules.group, required: true }} member="SqsParameters.MessageGroupId">
          <input name="group" required defaultValue={values?.group ?? "default"} />
        </FieldShell>
      )}
      {service === "kinesis" && (
        <FieldShell label="Partition key path">
          <input name="partitionKey" placeholder="$.detail.id" defaultValue={values?.partitionKey} />
        </FieldShell>
      )}
      {["sqs", "sns", "lambda", "logs"].includes(service ?? "") && (
        <label className="check">
          <input type="checkbox" name="grant" defaultChecked /> Allow the rule in the target&apos;s resource policy
        </label>
      )}
    </>
  );
}
