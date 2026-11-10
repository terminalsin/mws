"use client";

// The Subscribe sheet's fields: the endpoint's rule (ARN, email, E.164 phone
// number, http(s) URL) follows the chosen protocol, bare names expand to the
// ARN they mean, and close names of existing queues, functions, streams
// and roles are suggested.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { useMemo, useState } from "react";

import { endpointRule, PROTOCOLS, roleRule, scopeOf } from "./rules";

export interface Targets {
  sqs: string[];
  lambda: string[];
  firehose: string[];
  application: string[];
  roles: string[];
}

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
    </>
  );
}
