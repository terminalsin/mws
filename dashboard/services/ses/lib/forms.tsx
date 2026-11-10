"use client";

import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { freeName, MoreFields, PresetGallery } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { useState } from "react";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

export const EVENT_TYPES = ["SEND", "REJECT", "BOUNCE", "COMPLAINT", "DELIVERY", "OPEN", "CLICK", "RENDERING_FAILURE", "DELIVERY_DELAY", "SUBSCRIPTION"] as const;
const EVENT_LABELS: Record<string, string> = { RENDERING_FAILURE: "Rendering failure", DELIVERY_DELAY: "Delivery delay" };
const label = (t: string) => EVENT_LABELS[t] ?? t[0] + t.slice(1).toLowerCase();

export type DestinationKind = "sns" | "eventbridge" | "firehose" | "cloudwatch";
export interface DestinationDefaults {
  name?: string;
  kind: DestinationKind;
  enabled: boolean;
  events: string[];
  topic?: string;
  bus?: string;
  stream?: string;
  role?: string;
  dimension?: string;
  dimensionSource?: string;
  dimensionDefault?: string;
}

const ARN: Rule = { required: true, pattern: "^arn:aws[\\w-]*:", hint: "An ARN" };
const DIMENSION: Rule = { required: true, pattern: "^[\\w:-]{1,256}$", hint: "Letters, digits, _ - : only" };

const KINDS: { id: DestinationKind; label: string; icon: string; title: string }[] = [
  { id: "sns", label: "SNS", icon: "service/AmazonSimpleNotificationService", title: "Amazon SNS topic" },
  { id: "eventbridge", label: "EventBridge", icon: "service/AmazonEventBridge", title: "Amazon EventBridge event bus" },
  { id: "firehose", label: "Firehose", icon: "service/AmazonDataFirehose", title: "Amazon Data Firehose stream" },
  { id: "cloudwatch", label: "CloudWatch", icon: "service/AmazonCloudWatch", title: "Amazon CloudWatch metrics" },
];

/** An event destination: where events go (a logo per kind, each taking its
 * own target), and which events; the event list waits under More. */
export function DestinationFields({ defaults, topics, streams, editing, nameRule }: { defaults: DestinationDefaults; topics: string[]; streams: string[]; editing?: boolean; nameRule: Rule }) {
  const [kind, setKind] = useState<DestinationKind>(defaults.kind);
  return (
    <>
      {!editing && (
        <PresetGallery
          presets={KINDS.map((k) => ({ ...k, found: (k.id === "sns" && topics.length > 0) || (k.id === "firehose" && streams.length > 0) }))}
          chosen={kind}
          choose={(k) => setKind(k.id)}
          label="Destination"
          testId="destination-kind"
        />
      )}
      <input type="hidden" name="kind" value={kind} />
      {editing ? (
        <input type="hidden" name="destName" value={defaults.name} />
      ) : (
        <Field key={kind} label="Name" rule={nameRule} unique>
          <input name="destName" required defaultValue={defaults.name ?? freeName(`to-${kind}`, nameRule.taken ?? [])} />
        </Field>
      )}
      {kind === "sns" && (
        <Field label="SNS topic" rule={ARN} known={topics} member="TopicArn">
          <ResourcePicker kind="sns-topic" name="topic" required defaultValue={defaults.topic ?? topics[0]} />
        </Field>
      )}
      {kind === "eventbridge" && (
        <Field label="Event bus" hint="The default bus when empty" member="EventBusArn">
          <input name="bus" defaultValue={defaults.bus} placeholder="arn:aws:events:…:event-bus/default" />
        </Field>
      )}
      {kind === "firehose" && (
        <>
          <Field label="Delivery stream" rule={ARN} known={streams} member="DeliveryStreamArn">
            <ResourcePicker kind="firehose-stream" name="stream" required defaultValue={defaults.stream ?? streams[0]} />
          </Field>
          <Field label="IAM role SES assumes" rule={ARN} member="IamRoleArn">
            <ResourcePicker kind="iam-role" name="role" service="ses.amazonaws.com" required defaultValue={defaults.role} />
          </Field>
        </>
      )}
      {kind === "cloudwatch" && (
        <div className="form-row">
          <Field label="Dimension" rule={DIMENSION} member="DimensionName">
            <input name="dimension" required defaultValue={defaults.dimension ?? "ses:configuration-set"} />
          </Field>
          <Field label="Value source" member="DimensionValueSource">
            <select name="dimensionSource" defaultValue={defaults.dimensionSource ?? "MESSAGE_TAG"}>
              <option value="MESSAGE_TAG">Message tag</option>
              <option value="EMAIL_HEADER">Email header</option>
              <option value="LINK_TAG">Link tag</option>
            </select>
          </Field>
          <Field label="Default value" rule={DIMENSION} member="DefaultDimensionValue">
            <input name="dimensionDefault" required defaultValue={defaults.dimensionDefault ?? "none"} />
          </Field>
        </div>
      )}
      <label className="check">
        <input type="checkbox" name="enabled" defaultChecked={defaults.enabled} /> Enabled
      </label>
      <MoreFields label="Event types" expanded={editing}>
        <fieldset className="checks">
          <legend>Event types</legend>
          {EVENT_TYPES.map((t) => (
            <label className="check" key={t}>
              <input type="checkbox" name="event" value={t} defaultChecked={defaults.events.includes(t)} /> {label(t)}
            </label>
          ))}
        </fieldset>
      </MoreFields>
    </>
  );
}

export interface RuleDefaults {
  name?: string;
  enabled: boolean;
  scan: boolean;
  tls: string;
  recipients: string[];
  header?: { name: string; value: string };
  s3?: { bucket: string; prefix?: string; topic?: string };
  sns?: { topic: string; encoding?: string };
  lambda?: { fn: string; invocation?: string };
  bounce?: { code: string; status?: string; message: string; sender: string };
  stop?: boolean;
}

const RECIPIENTS: Rule = { pattern: "^\\s*([^\\s,@]+@)?[^\\s,@]+\\.[^\\s,@]+(\\s*[,\\s]\\s*([^\\s,@]+@)?[^\\s,@]+\\.[^\\s,@]+)*\\s*$", hint: "Addresses or domains, comma separated" };
const SMTP: Rule = { required: true, pattern: "^5\\d\\d$", hint: "A 5xx code" };
const STATUS: Rule = { pattern: "^5\\.\\d{1,3}\\.\\d{1,3}$", hint: "Like 5.1.1" };
const HEADER: Rule = { required: true, pattern: "^[A-Za-z0-9-]{1,50}$", hint: "Letters, digits and dashes" };

/** A receipt rule: recipients, then the actions SES runs, in order. */
export function RuleFields({
  defaults,
  editing,
  nameRule,
  others,
  topics,
  buckets,
  functions,
  identities,
}: {
  defaults: RuleDefaults;
  editing?: boolean;
  nameRule: Rule;
  others: string[];
  topics: string[];
  buckets: string[];
  functions: string[];
  identities: string[];
}) {
  const [on, setOn] = useState<Record<string, boolean>>({
    header: !!defaults.header,
    s3: !!defaults.s3,
    sns: !!defaults.sns,
    lambda: !!defaults.lambda,
    bounce: !!defaults.bounce,
    stop: !!defaults.stop,
  });
  const toggle = (k: string, title: string) => (
    <label className="check">
      <input type="checkbox" name={`do:${k}`} checked={on[k]} onChange={(e) => setOn({ ...on, [k]: e.target.checked })} /> {title}
    </label>
  );
  return (
    <>
      {editing ? (
        <input type="hidden" name="ruleName" value={defaults.name} />
      ) : (
        <div className="form-row">
          <Field label="Rule name" rule={nameRule} taken={others} unique>
            <input name="ruleName" required defaultValue={defaults.name} />
          </Field>
          {others.length > 0 && (
            <Field label="Position" member="After">
              <select name="after" defaultValue={others[others.length - 1]}>
                <option value="">First</option>
                {others.map((o) => (
                  <option key={o} value={o}>
                    After {o}
                  </option>
                ))}
              </select>
            </Field>
          )}
        </div>
      )}
      <Field label="Recipients" hint="Empty matches every recipient of your verified domains" rule={RECIPIENTS} known={identities} member="Recipients">
        <input name="recipients" defaultValue={defaults.recipients.join(", ")} placeholder="support@example.com, example.com" />
      </Field>
      <div className="form-row">
        <label className="check">
          <input type="checkbox" name="enabled" defaultChecked={defaults.enabled} /> Enabled
        </label>
        <label className="check">
          <input type="checkbox" name="scan" defaultChecked={defaults.scan} /> Spam and virus scanning
        </label>
        <Field label="TLS" member="TlsPolicy">
          <select name="tls" defaultValue={defaults.tls}>
            <option>Optional</option>
            <option>Require</option>
          </select>
        </Field>
      </div>
      <div role="group" aria-label="Actions">
        {toggle("header", "Add header")}
        {on.header && (
          <div className="form-row">
            <Field label="Header name" rule={HEADER} member="HeaderName">
              <input name="headerName" required defaultValue={defaults.header?.name ?? "X-Received-By"} />
            </Field>
            <Field label="Header value" rule={{ required: true, maxLength: 2048 }} member="HeaderValue">
              <input name="headerValue" required defaultValue={defaults.header?.value ?? "ses"} />
            </Field>
          </div>
        )}
        {toggle("s3", "Deliver to S3 bucket")}
        {on.s3 && (
          <div className="form-row">
            <Field label="Bucket" rule={{ required: true, minLength: 3, maxLength: 63 }} known={buckets} member="BucketName">
              <ResourcePicker kind="s3-bucket" name="bucket" required defaultValue={defaults.s3?.bucket ?? buckets[0]} />
            </Field>
            <Field label="Object key prefix" member="ObjectKeyPrefix">
              <input name="prefix" defaultValue={defaults.s3?.prefix} placeholder="inbound/" />
            </Field>
          </div>
        )}
        {toggle("sns", "Publish to SNS topic")}
        {on.sns && (
          <div className="form-row">
            <Field label="Topic" rule={ARN} known={topics} member="TopicArn">
              <ResourcePicker kind="sns-topic" name="topic" required defaultValue={defaults.sns?.topic ?? topics[0]} />
            </Field>
            <Field label="Encoding" member="Encoding">
              <select name="encoding" defaultValue={defaults.sns?.encoding ?? "UTF-8"}>
                <option>UTF-8</option>
                <option>Base64</option>
              </select>
            </Field>
          </div>
        )}
        {toggle("lambda", "Invoke Lambda function")}
        {on.lambda && (
          <div className="form-row">
            <Field label="Function" rule={ARN} known={functions} member="FunctionArn">
              <ResourcePicker kind="lambda-function" name="function" required defaultValue={defaults.lambda?.fn ?? functions[0]} />
            </Field>
            <Field label="Invocation" member="InvocationType">
              <select name="invocation" defaultValue={defaults.lambda?.invocation ?? "Event"}>
                <option value="Event">Event (asynchronous)</option>
                <option value="RequestResponse">RequestResponse</option>
              </select>
            </Field>
          </div>
        )}
        {toggle("bounce", "Return a bounce")}
        {on.bounce && (
          <>
            <div className="form-row">
              <Field label="SMTP reply code" rule={SMTP} member="SmtpReplyCode">
                <input name="smtpCode" required defaultValue={defaults.bounce?.code ?? "550"} />
              </Field>
              <Field label="Status code" rule={STATUS} member="StatusCode">
                <input name="statusCode" defaultValue={defaults.bounce?.status ?? "5.1.1"} />
              </Field>
            </div>
            <Field label="Message" rule={{ required: true }} member="Message">
              <input name="bounceMessage" required defaultValue={defaults.bounce?.message ?? "Mailbox does not exist"} />
            </Field>
            <Field label="Sender" rule={{ required: true, format: "email" }} known={identities.filter((i) => i.includes("@"))} member="Sender">
              <input name="bounceSender" required defaultValue={defaults.bounce?.sender} placeholder="mailer-daemon@example.com" />
            </Field>
          </>
        )}
        {toggle("stop", "Stop the rule set")}
      </div>
    </>
  );
}
