"use client";

// A new log group starts from what writes to it: picking a source fills
// the name's conventional prefix and a retention that suits it. KMS,
// tags and the storage class wait under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { CreateLogGroup, PutRetentionPolicy } from "@mws-dashboard/ui/model/logs";
import { MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import { useState } from "react";

import { RETENTION, retentionLabel } from "./retention";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

interface Source extends PresetItem {
  prefix: string;
  retention: number;
  placeholder: string;
}

const SOURCES: Source[] = [
  { id: "app", label: "Application", icon: "resource/AmazonCloudWatchLogs", prefix: "/app/", retention: 30, placeholder: "/app/api" },
  { id: "lambda", label: "Lambda", icon: "service/AWSLambda", prefix: "/aws/lambda/", retention: 14, placeholder: "/aws/lambda/my-function", title: "Where a function's logs go: /aws/lambda/<function>" },
  { id: "ecs", label: "ECS", icon: "service/AmazonElasticContainerService", prefix: "/ecs/", retention: 30, placeholder: "/ecs/web" },
  { id: "eks", label: "EKS", icon: "service/AmazonElasticKubernetesService", prefix: "/aws/eks/", retention: 30, placeholder: "/aws/eks/cluster/cluster" },
  { id: "api", label: "API Gateway", icon: "service/AmazonAPIGateway", prefix: "/aws/apigateway/", retention: 30, placeholder: "/aws/apigateway/access" },
  { id: "flow", label: "VPC Flow Logs", icon: "resource/AmazonVPCFlowLogs", prefix: "/vpc/flow-logs/", retention: 90, placeholder: "/vpc/flow-logs/main" },
  { id: "trail", label: "CloudTrail", icon: "service/AWSCloudTrail", prefix: "aws-cloudtrail-logs-", retention: 365, placeholder: "aws-cloudtrail-logs-audit", title: "Kept a year, for audits" },
];

export function GroupFields({ taken, keyArns, keyAliases }: { taken: string[]; keyArns: string[]; keyAliases: Record<string, string> }) {
  const [source, setSource] = useState<Source>(SOURCES[0]);
  return (
    <>
      <PresetGallery presets={SOURCES} chosen={source.id} choose={setSource} label="Source" size={26} />
      <div key={source.id} className="preset-fields">
        <FieldShell label="Name" rule={CreateLogGroup.logGroupName} taken={taken} generate={{ prefix: source.prefix }} unique>
          <input name="name" placeholder={source.placeholder} defaultValue={source.id === "app" ? undefined : source.prefix} autoFocus />
        </FieldShell>
        <FieldShell label="Retention" rule={PutRetentionPolicy.retentionInDays}>
          <select name="retention" defaultValue={String(source.retention)}>
            {RETENTION.map((d) => (
              <option key={d} value={d}>
                {retentionLabel(d)}
              </option>
            ))}
          </select>
        </FieldShell>
        <MoreFields>
          <FieldShell label="KMS key ARN" rule={{ ...CreateLogGroup.kmsKeyId, format: "arn" }} known={keyArns}>
            <ResourcePicker kind="kms-key" name="kms" exclude="AWS managed" />
          </FieldShell>
          <datalist id="create-kms-keys">
            {Object.entries(keyAliases).map(([alias, arn]) => (
              <option key={alias} value={arn}>
                {alias}
              </option>
            ))}
          </datalist>
          <FieldShell label="Tags" rule={{ ...CreateLogGroup.tags, format: "tags" }}>
            <textarea name="tags" rows={1} placeholder="team=payments" />
          </FieldShell>
          <label className="check">
            <input type="checkbox" name="infrequent" /> Infrequent Access
          </label>
          <label className="check">
            <input type="checkbox" name="protect" /> Deletion protection
          </label>
        </MoreFields>
      </div>
    </>
  );
}
