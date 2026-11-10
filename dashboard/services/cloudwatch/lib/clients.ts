import "server-only";

import { CloudWatchClient, DescribeAlarmsCommand, type Dimension } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient, DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { ListTopicsCommand, SNSClient } from "@aws-sdk/client-sns";
import { client, collect } from "@mws-dashboard/aws";
import type { Tone } from "@mws-dashboard/ui";
import { SERVICES } from "@mws-dashboard/ui";

export const logs = () => client(CloudWatchLogsClient);
export const cloudwatch = () => client(CloudWatchClient);
const sns = () => client(SNSClient);

/** SNS topic ARNs, the usual alarm actions. */
export async function topicArns() {
  const c = await sns();
  return collect((NextToken) => c.send(new ListTopicsCommand({ NextToken })), (r) => r.Topics?.map((t) => t.TopicArn!) ?? [], (r) => r.NextToken, 500);
}

export const groupHref = (name: string, extra: Record<string, string> = {}) => `/logs/group?${new URLSearchParams({ name, ...extra })}`;

export const ICONS = {
  logs: "resource/AmazonCloudWatchLogs",
  alarm: "resource/AmazonCloudWatchAlarm",
  metrics: "resource/AmazonCloudWatchMetricsInsights",
};

export const ALARM_TONE: Record<string, Tone> = { OK: "good", ALARM: "bad", INSUFFICIENT_DATA: "neutral" };

/** The service that writes a log group or owns a metric namespace, for its icon. */
export function sourceIcon(name: string): string | undefined {
  const m = name.match(/^\/aws\/([a-z0-9-]+)\//i) ?? name.match(/^AWS\/([A-Za-z0-9]+)/) ?? name.match(/^\/(ecs|eks|lambda|rds|codebuild)\//);
  if (!m) return undefined;
  const id = m[1].toLowerCase();
  const alias: Record<string, string> = { "vendedlogs": "cloudwatch", applicationelb: "elb", networkelb: "elb", elasticache: "elasticache", apigateway: "apigateway", ebs: "ec2", usage: "servicequotas", states: "events" };
  const key = alias[id] ?? id;
  return SERVICES.find((s) => s.id === key || s.endpoints.includes(key))?.icon;
}

export const dimsText = (dims: Dimension[] | undefined) => (dims ?? []).map((d) => `${d.Name}=${d.Value}`).join(", ");

export function metricHref(ns: string, name: string, dims: Dimension[] | undefined) {
  return `/metrics?${new URLSearchParams({ ns, metric: name, dims: JSON.stringify(dims ?? []) })}`;
}

export async function listGroups(prefix = "") {
  const c = await logs();
  return collect(
    (nextToken) => c.send(new DescribeLogGroupsCommand({ nextToken, ...(prefix ? { logGroupNamePrefix: prefix } : {}) })),
    (r) => r.logGroups,
    (r) => r.nextToken,
  );
}

export async function listAlarms() {
  const c = await cloudwatch();
  const pages = await collect(
    (NextToken) => c.send(new DescribeAlarmsCommand({ NextToken, AlarmTypes: ["MetricAlarm", "CompositeAlarm"] })),
    (r) => [r],
    (r) => r.NextToken,
  );
  return { metric: pages.flatMap((p) => p.MetricAlarms ?? []), composite: pages.flatMap((p) => p.CompositeAlarms ?? []) };
}

/** Log groups by what writes them. */
export const GROUP_KINDS = [
  { id: "functions", title: "Functions", prototype: "lambda function logs", rule: /^\/aws\/lambda\// },
  { id: "containers", title: "Containers", prototype: "ecs eks container kubernetes task logs", rule: /^\/(aws\/)?(ecs|eks|containerinsights)\b/ },
  { id: "databases", title: "Databases", prototype: "rds aurora database postgres mysql logs", rule: /^\/aws\/(rds|elasticache|docdb|redshift)\b/ },
  { id: "network", title: "Network", prototype: "vpc flow logs route53 dns query load balancer", rule: /(flow|vpc|route53|elb|dns)/i },
  { id: "aws", title: "AWS services", prototype: "aws service vended logs", rule: /^\/aws\// },
];
