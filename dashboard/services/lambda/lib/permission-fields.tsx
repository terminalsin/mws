"use client";

// "Add permission" opens on who calls the function: picking a service fills
// its principal, a free statement ID and offers that service's resources as
// the source. The account and action wait under More.

import type { Rule } from "@mws-dashboard/ui";
import { FieldShell as Field } from "@mws-dashboard/ui/fields";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";
import { MoreFields, PresetGallery, freeName } from "@mws-dashboard/ui/presets";
import type { ResourceKind } from "@mws-dashboard/ui/resources";
import { useState } from "react";

interface Caller {
  id: string;
  label: string;
  icon: string;
  principal: string;
  /** The ARN's service, to offer only matching sources. */
  arn?: string;
  /** The resources a picker offers as the source. */
  kind?: ResourceKind;
}

const CALLERS: Caller[] = [
  { id: "sns", label: "SNS", icon: "service/AmazonSimpleNotificationService", principal: "sns.amazonaws.com", arn: "sns", kind: "sns-topic" },
  { id: "events", label: "EventBridge", icon: "service/AmazonEventBridge", principal: "events.amazonaws.com", arn: "events", kind: "event-rule" },
  { id: "s3", label: "S3", icon: "service/AmazonSimpleStorageService", principal: "s3.amazonaws.com", arn: "s3", kind: "s3-bucket" },
  { id: "apigateway", label: "API Gateway", icon: "service/AmazonAPIGateway", principal: "apigateway.amazonaws.com", arn: "execute-api" },
  { id: "logs", label: "CloudWatch Logs", icon: "service/AmazonCloudWatch", principal: "logs.amazonaws.com", arn: "logs", kind: "log-group" },
  { id: "elb", label: "Load balancer", icon: "service/ElasticLoadBalancing", principal: "elasticloadbalancing.amazonaws.com", arn: "elasticloadbalancing", kind: "target-group" },
  { id: "cognito", label: "Cognito", icon: "service/AmazonCognito", principal: "cognito-idp.amazonaws.com", arn: "cognito-idp" },
  { id: "iot", label: "IoT Core", icon: "service/AWSIoTCore", principal: "iot.amazonaws.com", arn: "iot" },
  { id: "account", label: "Account", icon: "service/AWSIdentityandAccessManagement", principal: "" },
];

export function PermissionFields({
  sids,
  qualifiers,
  sources,
  rules,
  principals,
}: {
  sids: string[];
  qualifiers: string[];
  sources: string[];
  rules: Record<"sid" | "principal" | "sourceArn" | "sourceAccount" | "action", Rule>;
  principals: string[];
}) {
  const [caller, setCaller] = useState(CALLERS[0]);
  const matching = caller.arn ? sources.filter((s) => s.split(":")[2] === caller.arn) : sources;
  return (
    <>
      <PresetGallery presets={CALLERS} chosen={caller.id} choose={setCaller} label="Caller" testId="caller" />
      <div key={caller.id}>
        <div className="form-row">
          <Field label="Statement ID" rule={rules.sid} taken={sids} unique member="StatementId">
            <input name="sid" required spellCheck={false} defaultValue={freeName(`from-${caller.id}`, sids)} />
          </Field>
          <Field label="Principal" rule={rules.principal} known={principals} member="Principal">
            <input name="principal" required list="principals" defaultValue={caller.principal} placeholder={caller.principal || "123456789012"} spellCheck={false} />
          </Field>
        </div>
        <datalist id="principals">
          {principals.map((p) => (
            <option key={p} value={p} />
          ))}
        </datalist>
        {caller.arn && (
          <Field label="Source ARN" rule={rules.sourceArn} known={matching} member="SourceArn">
            {caller.kind ? (
              <ResourcePicker kind={caller.kind} name="sourceArn" use="arn" defaultValue={matching.length === 1 ? matching[0] : undefined} testId="permission-source" />
            ) : (
              <input name="sourceArn" spellCheck={false} list="permission-sources" defaultValue={matching.length === 1 ? matching[0] : undefined} placeholder={`arn:aws:${caller.arn}:…`} />
            )}
          </Field>
        )}
        <datalist id="permission-sources">
          {matching.map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
        <MoreFields>
          {!caller.arn && (
            <Field label="Source ARN" rule={rules.sourceArn} known={sources} member="SourceArn">
              <ResourcePicker
                kind={["sns-topic", "event-rule", "s3-bucket", "log-group", "target-group", "sqs-queue", "kinesis-stream"]}
                name="sourceArn"
                use="arn"
                placeholder="Search resources or paste an ARN"
              />
            </Field>
          )}
          <div className="form-row">
            {qualifiers.length > 0 && (
              <Field label="Version or alias">
                <select name="qualifier" defaultValue="">
                  <option value="">Unqualified</option>
                  {qualifiers.map((q) => (
                    <option key={q}>{q}</option>
                  ))}
                </select>
              </Field>
            )}
            <Field label="Source account" rule={rules.sourceAccount} member="SourceAccount">
              <input name="sourceAccount" inputMode="numeric" />
            </Field>
            <Field label="Action" rule={rules.action} member="Action">
              <select name="action" defaultValue="lambda:InvokeFunction">
                <option>lambda:InvokeFunction</option>
                <option>lambda:InvokeFunctionUrl</option>
                <option>lambda:GetFunction</option>
                <option>lambda:*</option>
              </select>
            </Field>
          </div>
        </MoreFields>
      </div>
    </>
  );
}
