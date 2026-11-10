"use client";

// The Subscribe sheet's fields: the endpoint's rule (ARN, email, E.164 phone
// number, http(s) URL) follows the chosen protocol, bare names expand to the
// ARN they mean, and close names of existing queues, functions, streams
// and roles are suggested.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { useMemo, useState } from "react";

import { DLQ_ARN, endpointRule, FILTER_POLICY, PROTOCOLS, roleRule, scopeOf } from "./rules";

export interface Targets {
  sqs: string[];
  lambda: string[];
  firehose: string[];
  application: string[];
  roles: string[];
}

/** Protocols that can take the message without SNS's JSON envelope. */
const RAW = ["sqs", "http", "https", "firehose"];

const PLACEHOLDER: Record<string, string> = {
  sqs: "Queue name or ARN",
  lambda: "Function name or ARN",
  firehose: "Stream name or ARN",
  application: "Endpoint ARN",
  email: "name@example.com",
  "email-json": "name@example.com",
  sms: "+14155550100",
  http: "http://",
  https: "https://",
};

export function SubscribeFields({ topicArn, fifo, targets }: { topicArn: string; fifo: boolean; targets: Targets }) {
  // FIFO topics deliver to SQS and Firehose only.
  const protocols = fifo ? PROTOCOLS.filter((p) => p === "sqs" || p === "firehose") : PROTOCOLS;
  const [protocol, setProtocol] = useState<string>("sqs");
  const scope = useMemo(() => scopeOf(topicArn), [topicArn]);
  const rule = useMemo(() => endpointRule(protocol, scope, fifo), [protocol, scope, fifo]);
  const role = useMemo(() => roleRule(scope), [scope]);
  const known = protocol in targets ? targets[protocol as keyof Targets] : undefined;
  return (
    <>
      <div className="form-row">
        <FieldShell label="Protocol">
          <select name="protocol" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            {protocols.map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
        </FieldShell>
        <FieldShell label="Endpoint" rule={rule} known={known} member="Endpoint">
          <input name="endpoint" required placeholder={PLACEHOLDER[protocol]} type={protocol === "sms" ? "tel" : "text"} />
        </FieldShell>
      </div>
      {protocol === "firehose" && (
        <FieldShell label="Subscription role" rule={role} known={targets.roles} member="SubscriptionRoleArn">
          <input name="role" required placeholder="Role name or ARN" />
        </FieldShell>
      )}
      {protocol === "sqs" && (
        <label className="check">
          <input type="checkbox" name="grant" defaultChecked /> Allow the topic in the queue policy
        </label>
      )}
      {protocol === "lambda" && (
        <label className="check">
          <input type="checkbox" name="grant" defaultChecked /> Allow the topic to invoke the function
        </label>
      )}
      <div className="form-row">
        <FieldShell label="Filter policy" rule={FILTER_POLICY} member="FilterPolicy">
          <textarea name="filter" rows={3} placeholder='{"type": ["order"]}' spellCheck={false} />
        </FieldShell>
        <FieldShell label="Filter on">
          <select name="filterScope" defaultValue="MessageAttributes">
            <option value="MessageAttributes">Message attributes</option>
            <option value="MessageBody">Message body</option>
          </select>
        </FieldShell>
      </div>
      {RAW.includes(protocol) && (
        <label className="check">
          <input type="checkbox" name="raw" /> Raw message delivery
        </label>
      )}
      <FieldShell label="Dead-letter queue" rule={DLQ_ARN} known={targets.sqs} member="RedrivePolicy">
        <input name="dlq" placeholder="Queue ARN" spellCheck={false} />
      </FieldShell>
    </>
  );
}
