import "server-only";

import { ListRolesCommand } from "@aws-sdk/client-iam";
import { ListStreamsCommand } from "@aws-sdk/client-kinesis";
import {
  GetPolicyCommand,
  ListAliasesCommand,
  ListEventSourceMappingsCommand,
  ListFunctionsCommand,
  ListLayersCommand,
  ListTagsCommand,
  ListVersionsByFunctionCommand,
} from "@aws-sdk/client-lambda";
import { ListQueuesCommand } from "@aws-sdk/client-sqs";
import { all, collect, region } from "@mws-dashboard/aws";

import { iam, kinesis, lambda, sqs } from "./clients";

/** Roles Lambda can assume (their trust policy names lambda.amazonaws.com). */
export async function lambdaRoles() {
  const client = await iam();
  const roles = await all((Marker) => client.send(new ListRolesCommand({ Marker })), (r) => r.Roles, (r) => (r.IsTruncated ? r.Marker : undefined));
  return roles.filter((r) => decodeURIComponent(r.AssumeRolePolicyDocument ?? "").includes("lambda.amazonaws.com"));
}

export async function listFunctions() {
  const client = await lambda();
  const fns = await all(
    (Marker) => client.send(new ListFunctionsCommand({ Marker })),
    (r) => r.Functions,
    (r) => r.NextMarker,
  );
  const tags = await Promise.all(fns.map((f) => client.send(new ListTagsCommand({ Resource: f.FunctionArn })).then((r) => r.Tags ?? {}, () => ({}))));
  return fns.map((f, i) => ({ ...f, tags: tags[i] as Record<string, string> }));
}

export async function mappings(FunctionName: string) {
  const client = await lambda();
  return all((Marker) => client.send(new ListEventSourceMappingsCommand({ FunctionName, Marker })), (r) => r.EventSourceMappings, (r) => r.NextMarker);
}

export async function versions(FunctionName: string) {
  const client = await lambda();
  return all((Marker) => client.send(new ListVersionsByFunctionCommand({ FunctionName, Marker })), (r) => r.Versions, (r) => r.NextMarker);
}

export async function aliases(FunctionName: string) {
  const client = await lambda();
  return all((Marker) => client.send(new ListAliasesCommand({ FunctionName, Marker })), (r) => r.Aliases, (r) => r.NextMarker);
}

export async function layers() {
  const client = await lambda();
  return all((Marker) => client.send(new ListLayersCommand({ Marker })), (r) => r.Layers, (r) => r.NextMarker);
}

export interface Statement {
  Sid?: string;
  Effect?: string;
  Principal?: string | { Service?: string | string[]; AWS?: string | string[] };
  Action?: string | string[];
  Resource?: string | string[];
  Condition?: Record<string, Record<string, string | string[]>>;
}

/** The function's resource-based policy statements (none when it has no policy). */
export async function policy(FunctionName: string, Qualifier?: string): Promise<{ statements: Statement[]; revision?: string }> {
  try {
    const out = await (await lambda()).send(new GetPolicyCommand({ FunctionName, Qualifier }));
    return { statements: (JSON.parse(out.Policy ?? "{}").Statement ?? []) as Statement[], revision: out.RevisionId };
  } catch (e) {
    if (e instanceof Error && e.name === "ResourceNotFoundException") return { statements: [] };
    throw e;
  }
}

const list = (v: string | string[] | undefined) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

export function principals(s: Statement): string[] {
  if (typeof s.Principal === "string") return [s.Principal];
  return [...list(s.Principal?.Service), ...list(s.Principal?.AWS)];
}

export function actions(s: Statement): string[] {
  return list(s.Action);
}

/** The source ARN a statement is scoped to (`AWS:SourceArn`), if any. */
export function sourceArn(s: Statement): string | undefined {
  for (const op of Object.values(s.Condition ?? {})) {
    for (const [k, v] of Object.entries(op)) if (k.toLowerCase() === "aws:sourcearn") return list(v)[0];
  }
  return undefined;
}

export function condition(s: Statement, key: string): string | undefined {
  for (const op of Object.values(s.Condition ?? {})) {
    for (const [k, v] of Object.entries(op)) if (k.toLowerCase() === key.toLowerCase()) return list(v)[0];
  }
  return undefined;
}

/** Push triggers: services the policy lets invoke the function (SNS,
 * EventBridge, S3...), as the AWS console's trigger list shows them. */
export function pushTriggers(statements: Statement[]) {
  return statements
    .filter((s) => s.Effect !== "Deny" && actions(s).some((a) => a === "lambda:InvokeFunction" || a === "lambda:*" || a === "*"))
    .flatMap((s) => principals(s).filter((p) => p.endsWith(".amazonaws.com")).map((p) => ({ sid: s.Sid ?? "", service: p.replace(/\.amazonaws\.com$/, ""), source: sourceArn(s) })));
}

/** What a trigger can read from: queues and streams, as ARNs. */
export async function eventSources(): Promise<string[]> {
  const none = (): string[] => [];
  const [queues, streams] = await Promise.all([
    sqs()
      .then((c) => collect((NextToken) => c.send(new ListQueuesCommand({ NextToken, MaxResults: 1000 })), (r) => r.QueueUrls, (r) => r.NextToken, 10_000))
      .then((urls) => urls, none),
    kinesis()
      .then((c) => all((NextToken) => c.send(new ListStreamsCommand({ NextToken })), (r) => r.StreamSummaries?.map((s) => s.StreamARN!), (r) => r.NextToken))
      .catch(none),
  ]);
  const r = await region();
  // A queue URL ends in /<account>/<name>.
  return [...queues.map((u) => u.split("/").slice(-2)).map(([account, name]) => `arn:aws:sqs:${r}:${account}:${name}`), ...streams];
}
