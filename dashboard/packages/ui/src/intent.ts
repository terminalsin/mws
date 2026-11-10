// The policy assistant: a plain description ("read the orders bucket, send
// to the jobs queue, require MFA") turned into policy statements. Pure and
// offline: services and verbs come from the words, resources from the real
// ones the pickers list, conditions from the phrases people use. Shared by
// the policy editor and anything else that drafts IAM from intent.

import type { ResourceKind, ResourceOption } from "./resources";

export interface DraftStatement {
  sid: string;
  effect: "Allow" | "Deny";
  actions: string[];
  resources: string[];
  principals: { type: "AWS" | "Service" | "Federated" | "*"; values: string[] }[];
  conditions: { op: string; key: string; values: string[] }[];
}

/** What the assistant understood, shown before it writes anything. */
export interface Draft {
  statements: DraftStatement[];
  /** Short notes: "S3 read on orders", "MFA required". */
  notes: string[];
}

type Verb = "read" | "write" | "delete" | "list" | "full" | "invoke" | "send" | "receive" | "publish" | "encrypt" | "decrypt" | "push" | "pull" | "start";

interface ServiceIntent {
  prefix: string;
  label: string;
  words: RegExp;
  kind?: ResourceKind;
  /** Verb when the clause names none. */
  default: Verb;
  verbs: Partial<Record<Verb, string[]>>;
  /** The service principal, for trust policies. */
  principal?: string;
}

const SERVICES: ServiceIntent[] = [
  {
    prefix: "s3",
    label: "S3",
    words: /\b(s3|buckets?|objects?|files?|uploads?)\b/,
    kind: "s3-bucket",
    default: "read",
    verbs: { read: ["GetObject", "ListBucket"], list: ["ListBucket", "ListAllMyBuckets"], write: ["PutObject", "GetObject", "ListBucket"], delete: ["DeleteObject"] },
    principal: "s3.amazonaws.com",
  },
  {
    prefix: "sqs",
    label: "SQS",
    words: /\b(sqs|queues?)\b/,
    kind: "sqs-queue",
    default: "receive",
    verbs: { send: ["SendMessage", "GetQueueUrl"], write: ["SendMessage", "GetQueueUrl"], receive: ["ReceiveMessage", "DeleteMessage", "GetQueueAttributes", "ChangeMessageVisibility"], read: ["ReceiveMessage", "DeleteMessage", "GetQueueAttributes"] },
  },
  {
    prefix: "sns",
    label: "SNS",
    words: /\b(sns|topics?|notifications?|notify)\b/,
    kind: "sns-topic",
    default: "publish",
    verbs: { publish: ["Publish"], send: ["Publish"], write: ["Publish"], read: ["GetTopicAttributes", "ListTopics", "ListSubscriptionsByTopic"], receive: ["Subscribe"] },
    principal: "sns.amazonaws.com",
  },
  {
    prefix: "lambda",
    label: "Lambda",
    words: /\b(lambdas?|functions?)\b/,
    kind: "lambda-function",
    default: "invoke",
    verbs: { invoke: ["InvokeFunction"], read: ["GetFunction", "ListFunctions"], write: ["UpdateFunctionCode", "UpdateFunctionConfiguration", "GetFunction"] },
    principal: "lambda.amazonaws.com",
  },
  {
    prefix: "kms",
    label: "KMS",
    words: /\b(kms|keys?|encryption)\b/,
    kind: "kms-key",
    default: "decrypt",
    verbs: { encrypt: ["Encrypt", "GenerateDataKey"], decrypt: ["Decrypt"], read: ["Decrypt", "DescribeKey"], write: ["Encrypt", "Decrypt", "GenerateDataKey"] },
  },
  {
    prefix: "logs",
    label: "Logs",
    words: /\b(logs?|logging|cloudwatch logs|log groups?)\b/,
    kind: "log-group",
    default: "write",
    verbs: { write: ["CreateLogGroup", "CreateLogStream", "PutLogEvents"], send: ["CreateLogStream", "PutLogEvents"], read: ["GetLogEvents", "FilterLogEvents", "DescribeLogGroups", "DescribeLogStreams", "StartQuery", "GetQueryResults"] },
    principal: "logs.amazonaws.com",
  },
  {
    prefix: "dynamodb",
    label: "DynamoDB",
    words: /\b(dynamo(db)?|tables?|items?)\b/,
    default: "read",
    verbs: { read: ["GetItem", "Query", "Scan", "BatchGetItem", "DescribeTable"], write: ["PutItem", "UpdateItem", "DeleteItem", "BatchWriteItem", "GetItem", "Query"], delete: ["DeleteItem"] },
  },
  {
    prefix: "secretsmanager",
    label: "Secrets Manager",
    words: /\b(secrets?|passwords?|credentials?)\b/,
    kind: "secret",
    default: "read",
    verbs: { read: ["GetSecretValue", "DescribeSecret"], write: ["PutSecretValue", "UpdateSecret", "DescribeSecret"] },
  },
  {
    prefix: "ssm",
    label: "Parameter Store",
    words: /\b(ssm|parameters?|params?|config)\b/,
    kind: "ssm-parameter",
    default: "read",
    verbs: { read: ["GetParameter", "GetParameters", "GetParametersByPath"], write: ["PutParameter"], delete: ["DeleteParameter"] },
  },
  {
    prefix: "kinesis",
    label: "Kinesis",
    words: /\b(kinesis|data streams?|streams?)\b/,
    kind: "kinesis-stream",
    default: "read",
    verbs: { write: ["PutRecord", "PutRecords", "DescribeStreamSummary"], send: ["PutRecord", "PutRecords"], read: ["GetRecords", "GetShardIterator", "DescribeStream", "DescribeStreamSummary", "ListShards"], receive: ["GetRecords", "GetShardIterator", "ListShards"] },
  },
  {
    prefix: "firehose",
    label: "Firehose",
    words: /\b(firehose|delivery streams?)\b/,
    kind: "firehose-stream",
    default: "write",
    verbs: { write: ["PutRecord", "PutRecordBatch"], send: ["PutRecord", "PutRecordBatch"] },
    principal: "firehose.amazonaws.com",
  },
  {
    prefix: "ecr",
    label: "ECR",
    words: /\b(ecr|images?|containers?|registry|docker)\b/,
    kind: "ecr-repository",
    default: "pull",
    verbs: {
      pull: ["GetAuthorizationToken", "BatchGetImage", "GetDownloadUrlForLayer", "BatchCheckLayerAvailability"],
      read: ["GetAuthorizationToken", "BatchGetImage", "GetDownloadUrlForLayer", "BatchCheckLayerAvailability"],
      push: ["GetAuthorizationToken", "BatchCheckLayerAvailability", "InitiateLayerUpload", "UploadLayerPart", "CompleteLayerUpload", "PutImage"],
      write: ["GetAuthorizationToken", "BatchCheckLayerAvailability", "InitiateLayerUpload", "UploadLayerPart", "CompleteLayerUpload", "PutImage"],
    },
  },
  {
    prefix: "events",
    label: "EventBridge",
    words: /\b(eventbridge|events?|event bus(es)?|buses)\b/,
    kind: "event-bus",
    default: "send",
    verbs: { send: ["PutEvents"], write: ["PutEvents"], publish: ["PutEvents"], read: ["DescribeEventBus", "ListRules"] },
    principal: "events.amazonaws.com",
  },
  {
    prefix: "cloudwatch",
    label: "CloudWatch",
    words: /\b(cloudwatch|metrics?|alarms?|dashboards?)\b/,
    default: "write",
    verbs: { write: ["PutMetricData"], send: ["PutMetricData"], read: ["GetMetricData", "ListMetrics", "DescribeAlarms"] },
  },
  {
    prefix: "ec2",
    label: "EC2",
    words: /\b(ec2|instances?|vms?|servers?)\b/,
    kind: "ec2-instance",
    default: "read",
    verbs: { read: ["DescribeInstances", "DescribeInstanceStatus"], list: ["DescribeInstances"], start: ["StartInstances", "StopInstances", "RebootInstances"], write: ["StartInstances", "StopInstances", "RebootInstances"] },
    principal: "ec2.amazonaws.com",
  },
  {
    prefix: "states",
    label: "Step Functions",
    words: /\b(step functions?|state machines?|workflows?)\b/,
    default: "start",
    verbs: { start: ["StartExecution"], invoke: ["StartExecution"], read: ["DescribeExecution", "ListExecutions"] },
    principal: "states.amazonaws.com",
  },
  {
    prefix: "bedrock",
    label: "Bedrock",
    words: /\b(bedrock|models?|llms?|ai|claude)\b/,
    default: "invoke",
    verbs: { invoke: ["InvokeModel", "InvokeModelWithResponseStream"], read: ["ListFoundationModels", "GetFoundationModel"] },
    principal: "bedrock.amazonaws.com",
  },
  {
    prefix: "ecs-tasks",
    label: "ECS tasks",
    words: /\b(ecs|tasks?|fargate)\b/,
    default: "read",
    verbs: {},
    principal: "ecs-tasks.amazonaws.com",
  },
];

const VERBS: [Verb, RegExp][] = [
  ["full", /\b(full|admin|administer|manage|everything|all access|anything)\b/],
  ["delete", /\b(delete|remove|purge)\b/],
  ["push", /\b(push|publish images?)\b/],
  ["pull", /\b(pull|download images?)\b/],
  ["publish", /\b(publish|notify|broadcast)\b/],
  ["send", /\b(send|put|emit|enqueue|produce|ship)\b/],
  ["receive", /\b(receive|consume|poll|process|dequeue|subscribe)\b/],
  ["invoke", /\b(invoke|call|trigger|run|execute|use|chat)\b/],
  ["start", /\b(start|stop|reboot)\b/],
  ["encrypt", /\b(encrypt|sign)\b/],
  ["decrypt", /\b(decrypt)\b/],
  ["write", /\b(write|upload|update|modify|change|create|save|store|edit)\b/],
  ["list", /\b(list|browse|enumerate)\b/],
  ["read", /\b(read|get|view|see|fetch|download|describe|look|access)\b/],
];

/** Split a description into clauses: "read X and write Y; deny Z". */
function clauses(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[;\n]|,\s*|\.\s+|\s+(?:and then|then|also|plus|and)\s+(?=(?:read|write|send|receive|publish|invoke|call|deny|never|block|list|delete|push|pull|start|use|encrypt|decrypt|get|put|consume|manage|full|admin|allow|let|require|only|from|in)\b)/)
    .map((c) => c.trim())
    .filter(Boolean);
}

function resourcesFor(svc: ServiceIntent, clause: string, known: ResourceOption[]): string[] {
  if (!svc.kind) return [];
  const words = new Set(clause.split(/[^a-z0-9._/-]+/).filter((w) => w.length >= 2));
  const mine = known.filter((o) => o.kind === svc.kind);
  // Names said exactly win; a partial match only counts when nothing matches exactly.
  const exact = mine.filter((o) => words.has(o.name.toLowerCase()));
  const hits = exact.length ? exact : mine.filter((o) => [...words].some((w) => w.length >= 3 && o.name.toLowerCase().includes(w) && !svc.words.test(w)));
  return hits.flatMap((o) => {
    const arn = o.arn ?? o.id ?? o.name;
    if (svc.kind === "s3-bucket") return [arn, `${arn}/*`];
    if (svc.kind === "log-group") return [`${arn}:*`];
    return [arn];
  });
}

const REGION = /\b([a-z]{2}(?:-gov)?-(?:north|south|east|west|central|northeast|southeast|northwest|southwest)-\d)\b/g;
const CIDR = /\b(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)\b/g;
const ACCOUNT = /\b(\d{12})\b/g;

/** Turn a description into statements of a policy of `kind`. */
export function draftPolicy(text: string, kind: "identity" | "resource" | "trust", known: ResourceOption[] = []): Draft {
  const notes: string[] = [];
  const statements: DraftStatement[] = [];
  const conditions: DraftStatement["conditions"] = [];
  const lower = text.toLowerCase();

  if (/\bmfa\b|multi-?factor|2fa/.test(lower)) {
    conditions.push({ op: "Bool", key: "aws:MultiFactorAuthPresent", values: ["true"] });
    notes.push("MFA required");
  }
  if (/\b(tls|https|secure transport|encrypted in transit)\b/.test(lower)) {
    conditions.push({ op: "Bool", key: "aws:SecureTransport", values: ["true"] });
    notes.push("TLS only");
  }
  const regions = [...lower.matchAll(REGION)].map((m) => m[1]);
  if (regions.length) {
    conditions.push({ op: "StringEquals", key: "aws:RequestedRegion", values: [...new Set(regions)] });
    notes.push(`Only in ${[...new Set(regions)].join(", ")}`);
  }
  const ips = [...text.matchAll(CIDR)].map((m) => (m[1].includes("/") ? m[1] : `${m[1]}/32`));
  if (ips.length) {
    conditions.push({ op: "IpAddress", key: "aws:SourceIp", values: [...new Set(ips)] });
    notes.push(`From ${ips.join(", ")}`);
  }
  const org = lower.match(/\b(o-[a-z0-9]{10,32})\b/);
  if (org) {
    conditions.push({ op: "StringEquals", key: "aws:PrincipalOrgID", values: [org[1]] });
    notes.push(`Organization ${org[1]}`);
  }

  if (kind === "trust") {
    const principals: DraftStatement["principals"] = [];
    const services = SERVICES.filter((s) => s.principal && s.words.test(lower)).map((s) => s.principal!);
    if (services.length) {
      principals.push({ type: "Service", values: [...new Set(services)] });
      notes.push(`Trusted by ${services.map((s) => s.replace(".amazonaws.com", "")).join(", ")}`);
    }
    const accounts = [...lower.matchAll(ACCOUNT)].map((m) => `arn:aws:iam::${m[1]}:root`);
    if (accounts.length) {
      principals.push({ type: "AWS", values: [...new Set(accounts)] });
      notes.push(`Accounts ${accounts.map((a) => a.split(":")[4]).join(", ")}`);
    }
    if (principals.length) statements.push({ sid: "", effect: "Allow", actions: ["sts:AssumeRole"], resources: [], principals, conditions: [...conditions] });
    const external = text.match(/external[ -]?id[:= ]+([\w+=,.@:/-]+)/i);
    if (external && statements[0]) {
      statements[0].conditions.push({ op: "StringEquals", key: "sts:ExternalId", values: [external[1]] });
      notes.push("External ID");
    }
    const repo = text.match(/github[^\w]+(?:repo\s+)?([\w.-]+\/[\w.-]+)/i);
    if (repo) {
      const branch = text.match(/\b(?:branch|on)\s+([\w./-]+)/i)?.[1];
      statements.push({
        sid: "GitHubActions",
        effect: "Allow",
        actions: ["sts:AssumeRoleWithWebIdentity"],
        resources: [],
        principals: [{ type: "Federated", values: ["arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"] }],
        conditions: [
          { op: "StringEquals", key: "token.actions.githubusercontent.com:aud", values: ["sts.amazonaws.com"] },
          { op: "StringLike", key: "token.actions.githubusercontent.com:sub", values: [`repo:${repo[1]}:${branch ? `ref:refs/heads/${branch}` : "*"}`] },
        ],
      });
      notes.push(`GitHub Actions in ${repo[1]}${branch ? ` on ${branch}` : ""}`);
    }
    return { statements, notes };
  }

  for (const clause of clauses(text)) {
    const deny = /\b(deny|never|block|prevent|forbid|cannot|can't|no)\b/.test(clause);
    const verbs = VERBS.filter(([, re]) => re.test(clause)).map(([v]) => v);
    for (const svc of SERVICES.filter((s) => s.words.test(clause) && Object.keys(s.verbs).length)) {
      const vs = verbs.length ? verbs : [svc.default];
      let actions: string[];
      if (vs.includes("full")) actions = [`${svc.prefix}:*`];
      else {
        actions = [...new Set(vs.flatMap((v) => svc.verbs[v] ?? (v === "list" ? svc.verbs.read : v === "pull" || v === "receive" ? svc.verbs.read : v === "push" || v === "send" || v === "publish" ? svc.verbs.write : []) ?? []))].map((a) => `${svc.prefix}:${a}`);
        if (!actions.length) actions = (svc.verbs[svc.default] ?? []).map((a) => `${svc.prefix}:${a}`);
      }
      const resources = resourcesFor(svc, clause, known);
      // ECR's token is account-wide: it never takes a repository ARN.
      const split = svc.prefix === "ecr" && resources.length && actions.includes("ecr:GetAuthorizationToken");
      if (split) {
        statements.push({ sid: "", effect: "Allow", actions: ["ecr:GetAuthorizationToken"], resources: ["*"], principals: [], conditions: [] });
        actions = actions.filter((a) => a !== "ecr:GetAuthorizationToken");
      }
      const level = vs.includes("full") ? "full access" : vs.filter((v) => svc.verbs[v] || v === "list").join("/") || svc.default;
      notes.push(`${deny ? "Deny " : ""}${svc.label} ${level}${resources.length ? ` on ${[...new Set(resources.map((r) => r.replace(/\/\*$|:\*$/, "").split(/[:/]/).pop()))].join(", ")}` : ""}`);
      statements.push({
        sid: "",
        effect: deny ? "Deny" : "Allow",
        actions,
        resources: resources.length ? resources : ["*"],
        principals: kind === "resource" ? [{ type: "AWS" as const, values: [...lower.matchAll(ACCOUNT)].map((m) => `arn:aws:iam::${m[1]}:root`) }].filter((p) => p.values.length) : [],
        conditions: [...conditions],
      });
    }
  }
  // Conditions alone ("require MFA") apply to everything as a guard rail.
  if (!statements.length && conditions.length && kind === "identity") {
    for (const c of conditions) {
      const negated = { ...c, op: c.op === "Bool" ? "BoolIfExists" : c.op === "IpAddress" ? "NotIpAddress" : c.op.replace(/^String/, "StringNot"), values: c.op === "Bool" ? ["false"] : c.values };
      statements.push({ sid: "", effect: "Deny", actions: ["*"], resources: ["*"], principals: [], conditions: [negated] });
    }
  }
  return { statements, notes };
}

/** The resource kinds a description mentions, to load before drafting. */
export function kindsIn(text: string): ResourceKind[] {
  const lower = text.toLowerCase();
  return [...new Set(SERVICES.filter((s) => s.kind && s.words.test(lower)).map((s) => s.kind!))];
}
