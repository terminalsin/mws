import "server-only";

import {
  CloudWatchClient,
  DescribeAlarmsCommand,
  type CompositeAlarm,
  type Dimension,
  type LogAlarm,
  type MetricAlarm,
} from "@aws-sdk/client-cloudwatch";
import {
  CloudWatchLogsClient,
  DescribeLogGroupsCommand,
} from "@aws-sdk/client-cloudwatch-logs";
import { ListTopicsCommand, SNSClient } from "@aws-sdk/client-sns";
import { all, client } from "@mws-dashboard/aws";
import type { Tone } from "@mws-dashboard/ui";
import { SERVICES } from "@mws-dashboard/ui";

export const logs = () => client(CloudWatchLogsClient);
export const cloudwatch = () => client(CloudWatchClient);
const sns = () => client(SNSClient);

/** SNS topic ARNs, the usual alarm actions. */
export async function topicArns() {
  const c = await sns();
  return all(
    (NextToken) => c.send(new ListTopicsCommand({ NextToken })),
    (r) => r.Topics?.map((t) => t.TopicArn!) ?? [],
    (r) => r.NextToken,
  );
}

export const groupHref = (name: string, extra: Record<string, string> = {}) =>
  `/logs/group?${new URLSearchParams({ name, ...extra })}`;

export const ICONS = {
  logs: "resource/AmazonCloudWatchLogs",
  alarm: "resource/AmazonCloudWatchAlarm",
  metrics: "resource/AmazonCloudWatchMetricsInsights",
};

export const ALARM_TONE: Record<string, Tone> = {
  OK: "good",
  ALARM: "bad",
  INSUFFICIENT_DATA: "neutral",
};

/** The service that writes a log group or owns a metric namespace, for its icon. */
export function sourceIcon(name: string): string | undefined {
  const m =
    name.match(/^\/aws\/([a-z0-9-]+)\//i) ??
    name.match(/^AWS\/([A-Za-z0-9]+)/) ??
    name.match(/^\/(ecs|eks|lambda|rds|codebuild)\//);
  if (!m) return undefined;
  const id = m[1].toLowerCase();
  const alias: Record<string, string> = {
    vendedlogs: "cloudwatch",
    applicationelb: "elb",
    networkelb: "elb",
    elasticache: "elasticache",
    apigateway: "apigateway",
    ebs: "ec2",
    usage: "servicequotas",
    states: "events",
  };
  const key = alias[id] ?? id;
  return SERVICES.find((s) => s.id === key || s.endpoints.includes(key))?.icon;
}

export const dimsText = (dims: Dimension[] | undefined) =>
  (dims ?? []).map((d) => `${d.Name}=${d.Value}`).join(", ");

export function metricHref(
  ns: string,
  name: string,
  dims: Dimension[] | undefined,
) {
  return `/metrics?${new URLSearchParams({ ns, metric: name, dims: JSON.stringify(dims ?? []) })}`;
}

export async function listGroups(prefix = "") {
  const c = await logs();
  return all(
    (nextToken) =>
      c.send(
        new DescribeLogGroupsCommand({
          nextToken,
          ...(prefix ? { logGroupNamePrefix: prefix } : {}),
        }),
      ),
    (r) => r.logGroups,
    (r) => r.nextToken,
  );
}

export type AnyAlarm =
  | (MetricAlarm & { kind: "metric" })
  | (CompositeAlarm & { kind: "composite" })
  | (LogAlarm & { kind: "log" });

/** Every alarm of every type (metric, composite and log alarms). */
export async function listAlarms(): Promise<AnyAlarm[]> {
  const c = await cloudwatch();
  const pages = await all(
    (NextToken) =>
      c.send(
        new DescribeAlarmsCommand({
          NextToken,
          AlarmTypes: ["MetricAlarm", "CompositeAlarm", "LogAlarm"],
        }),
      ),
    (r) => [r],
    (r) => r.NextToken,
  );
  return [
    ...pages.flatMap((p) =>
      (p.MetricAlarms ?? []).map((a) => ({ ...a, kind: "metric" as const })),
    ),
    ...pages.flatMap((p) =>
      (p.CompositeAlarms ?? []).map((a) => ({
        ...a,
        kind: "composite" as const,
      })),
    ),
    ...pages.flatMap((p) =>
      (p.LogAlarms ?? []).map((a) => ({ ...a, kind: "log" as const })),
    ),
  ];
}

export const alarmHref = (name: string, tab?: string) =>
  `/alarms/alarm?${new URLSearchParams({ name, ...(tab ? { tab } : {}) })}`;

/** The console page of the resource an ARN names, when the console has one
 * (alarm actions, subscription destinations, KMS keys, roles). */
export function arnHref(arn: string | undefined): string | undefined {
  if (!arn) return undefined;
  const [, , svc, , , ...rest] = arn.split(":");
  const res = rest.join(":");
  switch (svc) {
    case "sns":
      return `/sns/topic?${new URLSearchParams({ arn })}`;
    case "lambda":
      return `/lambda/${encodeURIComponent(res.replace(/^function:/, "").split(":")[0])}`;
    case "kinesis":
      return res.startsWith("stream/")
        ? `/kinesis/stream?${new URLSearchParams({ name: res.slice(7).split("/")[0] })}`
        : undefined;
    case "firehose":
      return res.startsWith("deliverystream/")
        ? `/firehose/stream?${new URLSearchParams({ name: res.slice(15) })}`
        : undefined;
    case "kms":
      return `/kms/key?${new URLSearchParams({ id: res.replace(/^key\//, "") })}`;
    case "iam":
      return res.startsWith("role/")
        ? `/iam/roles/${encodeURIComponent(res.split("/").pop()!)}`
        : undefined;
    case "s3":
      return `/s3/${encodeURIComponent(res.split("/")[0])}`;
    case "logs":
      return res.startsWith("log-group:")
        ? groupHref(res.slice(10).replace(/:\*$/, ""))
        : undefined;
    case "cloudwatch":
      return res.startsWith("alarm:") ? alarmHref(res.slice(6)) : undefined;
    default:
      return undefined;
  }
}

/** The icon of the service an ARN belongs to. */
export function arnIcon(arn: string | undefined): string {
  const svc = arn?.split(":")[2] ?? "";
  const map: Record<string, string> = {
    sns: "resource/AmazonSimpleNotificationServiceTopic",
    lambda: "resource/AWSLambdaLambdaFunction",
    kinesis: "service/AmazonKinesisDataStreams",
    firehose: "service/AmazonDataFirehose",
    logs: "resource/AmazonCloudWatchLogs",
    autoscaling: "service/AmazonEC2AutoScaling",
    automate: "service/AmazonEC2",
    ssm: "service/AWSSystemsManager",
    cloudwatch: "resource/AmazonCloudWatchAlarm",
  };
  return (
    map[svc] ??
    SERVICES.find((s) => s.endpoints.includes(svc))?.icon ??
    "service/AmazonCloudWatch"
  );
}

/** The short name at the end of an ARN. */
export const arnName = (arn: string) => arn.split(/[:/]/).pop() ?? arn;

/** Log groups by what writes them. */
export const GROUP_KINDS = [
  {
    id: "functions",
    title: "Functions",
    prototype: "lambda function logs",
    rule: /^\/aws\/lambda\//,
  },
  {
    id: "containers",
    title: "Containers",
    prototype: "ecs eks container kubernetes task logs",
    rule: /^\/(aws\/)?(ecs|eks|containerinsights)\b/,
  },
  {
    id: "databases",
    title: "Databases",
    prototype: "rds aurora database postgres mysql logs",
    rule: /^\/aws\/(rds|elasticache|docdb|redshift)\b/,
  },
  {
    id: "network",
    title: "Network",
    prototype: "vpc flow logs route53 dns query load balancer",
    rule: /(flow|vpc|route53|elb|dns)/i,
  },
  {
    id: "aws",
    title: "AWS services",
    prototype: "aws service vended logs",
    rule: /^\/aws\//,
  },
];
