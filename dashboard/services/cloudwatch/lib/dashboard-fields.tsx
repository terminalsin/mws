"use client";

// A new dashboard starts from what it watches: blank, or one service's
// key metrics (SEARCH widgets, so every function, queue or instance shows
// up without naming it). The JSON source waits under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { PutDashboard } from "@mws-dashboard/ui/model/cloudwatch";
import { freeName, MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui/validation";
import { LayoutDashboard } from "lucide-react";
import { useState } from "react";

// PutDashboard: "Dashboard names can contain only alphanumerics, dash (-) and underscore (_)."
const NAME: Rule = { ...PutDashboard.DashboardName, pattern: "^[A-Za-z0-9_-]+$", maxLength: 255, hint: "Letters, digits, - and _" };

type Graph = [title: string, namespace: string, dimension: string, metric: string, stat: string];

interface Kind extends PresetItem {
  base: string;
  graphs: Graph[];
}

const KINDS: Kind[] = [
  { id: "blank", label: "Blank", icon: <LayoutDashboard size={24} aria-hidden />, base: "dashboard", graphs: [] },
  {
    id: "lambda",
    label: "Lambda",
    icon: "service/AWSLambda",
    base: "functions",
    graphs: [
      ["Invocations", "AWS/Lambda", "FunctionName", "Invocations", "Sum"],
      ["Errors", "AWS/Lambda", "FunctionName", "Errors", "Sum"],
      ["Duration p99", "AWS/Lambda", "FunctionName", "Duration", "p99"],
      ["Throttles", "AWS/Lambda", "FunctionName", "Throttles", "Sum"],
    ],
  },
  {
    id: "sqs",
    label: "SQS",
    icon: "service/AmazonSimpleQueueService",
    base: "queues",
    graphs: [
      ["Messages waiting", "AWS/SQS", "QueueName", "ApproximateNumberOfMessagesVisible", "Maximum"],
      ["Oldest message (s)", "AWS/SQS", "QueueName", "ApproximateAgeOfOldestMessage", "Maximum"],
      ["Sent", "AWS/SQS", "QueueName", "NumberOfMessagesSent", "Sum"],
      ["Deleted", "AWS/SQS", "QueueName", "NumberOfMessagesDeleted", "Sum"],
    ],
  },
  {
    id: "ec2",
    label: "EC2",
    icon: "service/AmazonEC2",
    base: "instances",
    graphs: [
      ["CPU %", "AWS/EC2", "InstanceId", "CPUUtilization", "Average"],
      ["Network in", "AWS/EC2", "InstanceId", "NetworkIn", "Sum"],
      ["Network out", "AWS/EC2", "InstanceId", "NetworkOut", "Sum"],
      ["Status checks failed", "AWS/EC2", "InstanceId", "StatusCheckFailed", "Maximum"],
    ],
  },
  {
    id: "rds",
    label: "RDS",
    icon: "service/AmazonRDS",
    base: "databases",
    graphs: [
      ["CPU %", "AWS/RDS", "DBInstanceIdentifier", "CPUUtilization", "Average"],
      ["Connections", "AWS/RDS", "DBInstanceIdentifier", "DatabaseConnections", "Maximum"],
      ["Free storage", "AWS/RDS", "DBInstanceIdentifier", "FreeStorageSpace", "Minimum"],
      ["Read latency", "AWS/RDS", "DBInstanceIdentifier", "ReadLatency", "Average"],
    ],
  },
];

function body(kind: Kind, region: string) {
  const widgets: Record<string, unknown>[] = [
    { type: "text", x: 0, y: 0, width: 24, height: 2, properties: { markdown: kind.graphs.length ? `# ${kind.label}` : "# My dashboard" } },
    ...kind.graphs.map(([title, ns, dim, metric, stat], i) => ({
      type: "metric",
      x: (i % 2) * 12,
      y: 2 + Math.floor(i / 2) * 6,
      width: 12,
      height: 6,
      properties: {
        title,
        region,
        view: "timeSeries",
        period: 300,
        metrics: [[{ expression: `SEARCH('{${ns},${dim}} MetricName="${metric}"', '${stat}', 300)`, id: "e1" }]],
      },
    })),
  ];
  return JSON.stringify({ widgets }, null, 2);
}

export function DashboardFields({ taken, region, namespaces }: { taken: string[]; region: string; namespaces: string[] }) {
  const [kind, setKind] = useState<Kind>(KINDS[0]);
  return (
    <>
      <PresetGallery
        presets={KINDS.map((k) => ({ ...k, found: k.graphs.length > 0 && namespaces.includes(k.graphs[0][1]) }))}
        chosen={kind.id}
        choose={(k) => setKind(KINDS.find((x) => x.id === k.id)!)}
        label="Dashboard"
        size={24}
      />
      <div key={kind.id} className="preset-fields">
        <FieldShell label="Name" rule={NAME} taken={taken} generate="name" unique>
          <input name="name" autoFocus defaultValue={kind.id === "blank" ? undefined : freeName(kind.base, taken)} />
        </FieldShell>
        <MoreFields label="Source">
          <FieldShell label="Source" rule={{ ...PutDashboard.DashboardBody, required: false, format: "json" }}>
            <textarea name="body" rows={10} className="code-editor" spellCheck={false} defaultValue={body(kind, region)} />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}
