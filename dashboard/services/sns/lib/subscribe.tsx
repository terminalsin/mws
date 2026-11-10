"use client";

// The Subscribe sheet's fields: the endpoint's rule (ARN, email, E.164 phone
// number, http(s) URL) follows the chosen protocol, bare names expand to the
// ARN they mean, and close names of existing queues, functions, streams
// and roles are suggested.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import { Braces, Globe, Lock, Mail, MessageSquare, Smartphone } from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";

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

const TILE: Record<string, { label: string; icon: string | ReactNode; group: string }> = {
  sqs: { label: "SQS", icon: "service/AmazonSimpleQueueService", group: "AWS" },
  lambda: { label: "Lambda", icon: "service/AWSLambda", group: "AWS" },
  firehose: { label: "Firehose", icon: "service/AmazonDataFirehose", group: "AWS" },
  application: { label: "Mobile push", icon: <Smartphone size={26} aria-hidden />, group: "AWS" },
  email: { label: "Email", icon: <Mail size={26} aria-hidden />, group: "People and webhooks" },
  "email-json": { label: "Email (JSON)", icon: <Braces size={26} aria-hidden />, group: "People and webhooks" },
  sms: { label: "SMS", icon: <MessageSquare size={26} aria-hidden />, group: "People and webhooks" },
  https: { label: "HTTPS", icon: <Lock size={26} aria-hidden />, group: "People and webhooks" },
  http: { label: "HTTP", icon: <Globe size={26} aria-hidden />, group: "People and webhooks" },
};

const ORDER = ["sqs", "lambda", "firehose", "application", "email", "email-json", "sms", "https", "http"];

export function SubscribeFields({ topicArn, fifo, targets }: { topicArn: string; fifo: boolean; targets: Targets }) {
  // FIFO topics deliver to SQS and Firehose only.
  const protocols = ORDER.filter((p) => (PROTOCOLS as readonly string[]).includes(p) && (!fifo || p === "sqs" || p === "firehose"));
  const [protocol, setProtocol] = useState<string>("sqs");
  const scope = useMemo(() => scopeOf(topicArn), [topicArn]);
  const rule = useMemo(() => endpointRule(protocol, scope, fifo), [protocol, scope, fifo]);
  const role = useMemo(() => roleRule(scope), [scope]);
  const known = protocol in targets ? targets[protocol as keyof Targets] : undefined;
  return (
    <>
      <PresetGallery
        presets={protocols.map((p) => ({ id: p, ...TILE[p], found: (targets[p as keyof Targets]?.length ?? 0) > 0 }))}
        chosen={protocol}
        choose={(p) => setProtocol(p.id)}
        label="Protocol"
        testId="protocol"
      />
      <input type="hidden" name="protocol" value={protocol} />
      <FieldShell label="Endpoint" rule={rule} known={known} member="Endpoint">
        <input name="endpoint" required placeholder={PLACEHOLDER[protocol]} type={protocol === "sms" ? "tel" : "text"} list={known?.length ? "sns-endpoints" : undefined} spellCheck={false} />
      </FieldShell>
      {known && known.length > 0 && (
        <datalist id="sns-endpoints">
          {known.map((k) => (
            <option key={k} value={k} />
          ))}
        </datalist>
      )}
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
      {RAW.includes(protocol) && (
        <label className="check">
          <input type="checkbox" name="raw" /> Raw message delivery
        </label>
      )}
      <FieldShell label="Filter policy" rule={FILTER_POLICY} member="FilterPolicy">
        <textarea name="filter" rows={2} placeholder='{"type": ["order"]}' spellCheck={false} />
      </FieldShell>
      <MoreFields>
        <div className="form-row">
          <FieldShell label="Filter on">
            <select name="filterScope" defaultValue="MessageAttributes">
              <option value="MessageAttributes">Message attributes</option>
              <option value="MessageBody">Message body</option>
            </select>
          </FieldShell>
          <FieldShell label="Dead-letter queue" rule={DLQ_ARN} known={targets.sqs} member="RedrivePolicy">
            <input name="dlq" placeholder="Queue ARN" spellCheck={false} />
          </FieldShell>
        </div>
      </MoreFields>
    </>
  );
}
