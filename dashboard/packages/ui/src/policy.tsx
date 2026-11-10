"use client";

// The policy editor: IAM JSON with a visual builder over it. Each statement
// is a card (Allow or Deny, actions searched from every service MWS serves,
// resources picked from the real ones, conditions from the common keys),
// and the JSON underneath stays the form's value, so pasting a document,
// validation and server errors work as with a plain textarea.
//
//   <PolicyEditor label="Document" name="document" rule={RULES.document} defaultValue={json} />
//   <PolicyEditor kind="trust" ... />     // principals, sts:AssumeRole*
//   <PolicyEditor kind="resource" ... />  // principals, actions and resources

import { Braces, LayoutList, Plus, Sparkles, Trash2, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

import { iconUrl } from "./catalog";
import { FieldShell, setControlValue, type FieldRules } from "./fields";
import { ACTIONS, ACTION_SERVICES } from "./model/actions";
import { draftPolicy, kindsIn, type DraftStatement } from "./intent";
import { ResourcePicker, useResources } from "./pickers";
import type { ResourceKind } from "./resources";

// ---------------------------------------------------------------------------
// Actions.

/** IAM actions with no API operation of their own (permission-only actions
 * and the S3 names that differ from its operations), plus services people
 * write policies for that MWS does not serve. */
const EXTRA_ACTIONS: Record<string, string[]> = {
  iam: ["PassRole"],
  s3: ["ListBucket", "ListAllMyBuckets", "ListBucketVersions", "ListBucketMultipartUploads", "GetObjectVersion", "DeleteObjectVersion", "GetBucketLocation"],
  lambda: ["InvokeFunctionUrl"],
  sts: ["TagSession", "SetSourceIdentity"],
  dynamodb: ["GetItem", "PutItem", "UpdateItem", "DeleteItem", "Query", "Scan", "BatchGetItem", "BatchWriteItem", "DescribeTable", "ConditionCheckItem"],
  states: ["StartExecution", "DescribeExecution", "StopExecution", "ListExecutions", "SendTaskSuccess", "SendTaskFailure"],
  "execute-api": ["Invoke", "ManageConnections"],
  ssmmessages: ["CreateControlChannel", "CreateDataChannel", "OpenControlChannel", "OpenDataChannel"],
  "ec2messages": ["AcknowledgeMessage", "GetMessages", "SendReply"],
};

const ALL_ACTIONS: Record<string, string[]> = (() => {
  const out: Record<string, string[]> = {};
  for (const [p, a] of Object.entries(ACTIONS)) out[p] = [...a];
  for (const [p, a] of Object.entries(EXTRA_ACTIONS)) out[p] = [...new Set([...(out[p] ?? []), ...a])].sort();
  return out;
})();

const SERVICE_ICONS: Record<string, string> = {
  s3: "service/AmazonSimpleStorageService",
  sqs: "service/AmazonSimpleQueueService",
  sns: "service/AmazonSimpleNotificationService",
  lambda: "service/AWSLambda",
  kms: "service/AWSKeyManagementService",
  iam: "service/AWSIdentityandAccessManagement",
  sts: "service/AWSIdentityandAccessManagement",
  logs: "resource/AmazonCloudWatchLogs",
  cloudwatch: "service/AmazonCloudWatch",
  ec2: "service/AmazonEC2",
  ecr: "service/AmazonElasticContainerRegistry",
  ecs: "service/AmazonElasticContainerService",
  eks: "service/AmazonElasticKubernetesService",
  dynamodb: "service/AmazonDynamoDB",
  secretsmanager: "service/AWSSecretsManager",
  ssm: "service/AWSSystemsManager",
  kinesis: "service/AmazonKinesisDataStreams",
  firehose: "service/AmazonDataFirehose",
  events: "service/AmazonEventBridge",
  states: "service/AWSStepFunctions",
  bedrock: "service/AmazonBedrock",
  rds: "service/AmazonRDS",
  elasticache: "service/AmazonElastiCache",
  route53: "service/AmazonRoute53",
  acm: "service/AWSCertificateManager",
  "acm-pca": "service/AWSPrivateCertificateAuthority",
  cloudformation: "service/AWSCloudFormation",
  cloudtrail: "service/AWSCloudTrail",
  elasticloadbalancing: "service/ElasticLoadBalancing",
  autoscaling: "resource/AmazonEC2AutoScaling",
  elasticfilesystem: "service/AmazonEFS",
  ses: "service/AmazonSimpleEmailService",
  organizations: "service/AWSOrganizations",
  guardduty: "service/AmazonGuardDuty",
  securityhub: "service/AWSSecurityHub",
};

export const serviceIcon = (prefix: string) => SERVICE_ICONS[prefix] ?? "category/ManagementTools";

/** Read, write, list, tagging or permissions, from the action's verb (close
 * to the access levels AWS's console groups actions by). */
export function accessLevel(action: string): "List" | "Read" | "Write" | "Tagging" | "Permissions" {
  const a = action.split(":").pop() ?? action;
  if (/^(Tag|Untag)/.test(a)) return "Tagging";
  if (/(Policy|Permission|Grant|Acl)s?$|^(Attach|Detach)(Role|User|Group)Policy|^PassRole$|^(Create|Retire|Revoke)Grant/.test(a)) return "Permissions";
  if (/^List/.test(a)) return "List";
  if (/^(Get|Describe|Head|Lookup|Search|Select|BatchGet|Query|Scan|Check|Validate|Estimate|Simulate|Preview|Test|Receive|Download|Export|View|Filter|Decrypt|Verify|GenerateDataKey|Invoke|Retrieve|Read|Discover|Poll|Batch(Check|Describe)|Sign|Encrypt|Assume)/.test(a))
    return a.startsWith("Invoke") || a.startsWith("Assume") || a.startsWith("Encrypt") || a.startsWith("Sign") || a.startsWith("Decrypt") || a.startsWith("GenerateDataKey") || a.startsWith("Receive") ? "Write" : "Read";
  return "Write";
}

function searchActions(q: string, limit = 40): string[] {
  const query = q.trim().toLowerCase();
  if (!query) return [];
  let [p, rest] = query.includes(":") ? query.split(":", 2) : [null, query];
  // "kms gen": the first word names the service.
  const first = query.split(/\s+/)[0];
  if (p === null && query.includes(" ") && ALL_ACTIONS[first]) [p, rest] = [first, query.slice(first.length)];
  const words = (rest ?? "").split(/\s+/).filter(Boolean);
  const out: { a: string; s: number }[] = [];
  for (const [prefix, list] of Object.entries(ALL_ACTIONS)) {
    if (p !== null && !prefix.startsWith(p)) continue;
    const svcHit = p === null && (prefix === query || prefix.startsWith(query) || (ACTION_SERVICES[prefix] ?? "").toLowerCase().includes(query));
    for (const a of list) {
      const lower = a.toLowerCase();
      let s = 0;
      if (svcHit) s = 3;
      else if (!words.length) s = 2;
      else if (words.every((w) => lower.includes(w))) s = lower.startsWith(words[0]) ? 5 : 4;
      if (s) out.push({ a: `${prefix}:${a}`, s });
    }
  }
  return out.sort((x, y) => y.s - x.s || x.a.localeCompare(y.a)).slice(0, limit).map((x) => x.a);
}

/** The resource kind whose ARNs a service's actions take, for the picker. */
const RESOURCE_FOR: Record<string, ResourceKind> = {
  s3: "s3-bucket",
  sqs: "sqs-queue",
  sns: "sns-topic",
  lambda: "lambda-function",
  kms: "kms-key",
  logs: "log-group",
  kinesis: "kinesis-stream",
  firehose: "firehose-stream",
  secretsmanager: "secret",
  ssm: "ssm-parameter",
  "acm-pca": "private-ca",
  acm: "certificate",
  events: "event-bus",
  ecr: "ecr-repository",
  iam: "iam-role",
  sts: "iam-role",
  elasticloadbalancing: "target-group",
};

// ---------------------------------------------------------------------------
// The document model.

type PrincipalType = "AWS" | "Service" | "Federated" | "*";

interface Condition {
  op: string;
  key: string;
  values: string[];
}

interface Statement {
  uid: number;
  sid: string;
  effect: "Allow" | "Deny";
  actions: string[];
  resources: string[];
  principals: { type: PrincipalType; values: string[] }[];
  conditions: Condition[];
  /** A statement the builder does not model (NotAction, NotResource, ...): kept as JSON. */
  raw?: object;
}

let uid = 0;
const list = (v: unknown): string[] => (v === undefined ? [] : Array.isArray(v) ? v.map(String) : [String(v)]);
const one = (v: string[]) => (v.length === 1 ? v[0] : v);

function parse(text: string): { version: string; statements: Statement[] } | null {
  let doc: { Version?: string; Statement?: unknown };
  try {
    doc = JSON.parse(text || "{}");
  } catch {
    return null;
  }
  if (!doc || typeof doc !== "object") return null;
  const raw = doc.Statement === undefined ? [] : Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
  const statements = raw.map((s: Record<string, unknown>): Statement => {
    const known = new Set(["Sid", "Effect", "Action", "Resource", "Principal", "Condition"]);
    const unknown = Object.keys(s ?? {}).some((k) => !known.has(k));
    const p = s?.Principal;
    const principals: Statement["principals"] =
      p === "*" ? [{ type: "*", values: [] }] : p && typeof p === "object" ? Object.entries(p as Record<string, unknown>).map(([type, v]) => ({ type: type as PrincipalType, values: list(v) })) : [];
    const conditions: Condition[] = [];
    const c = s?.Condition as Record<string, Record<string, unknown>> | undefined;
    if (c && typeof c === "object") for (const [op, keys] of Object.entries(c)) for (const [key, v] of Object.entries(keys ?? {})) conditions.push({ op, key, values: list(v) });
    return {
      uid: ++uid,
      sid: typeof s?.Sid === "string" ? s.Sid : "",
      effect: s?.Effect === "Deny" ? "Deny" : "Allow",
      actions: list(s?.Action),
      resources: list(s?.Resource),
      principals,
      conditions,
      raw: unknown ? s : undefined,
    };
  });
  return { version: doc.Version ?? "2012-10-17", statements };
}

function serialize(version: string, statements: Statement[], kind: PolicyKind): string {
  const out = statements.map((s) => {
    if (s.raw) return s.raw;
    const o: Record<string, unknown> = {};
    if (s.sid) o.Sid = s.sid;
    o.Effect = s.effect;
    if (kind !== "identity" && s.principals.length) {
      o.Principal = s.principals.some((p) => p.type === "*") ? "*" : Object.fromEntries(s.principals.filter((p) => p.values.length).map((p) => [p.type, one(p.values)]));
    }
    o.Action = one(s.actions);
    if (kind !== "trust" || s.resources.length) o.Resource = one(s.resources.length ? s.resources : ["*"]);
    if (kind === "trust") delete o.Resource;
    if (s.conditions.length) {
      const c: Record<string, Record<string, string | string[]>> = {};
      for (const cond of s.conditions) if (cond.key) (c[cond.op] ??= {})[cond.key] = one(cond.values);
      if (Object.keys(c).length) o.Condition = c;
    }
    return o;
  });
  return JSON.stringify({ Version: version, Statement: out }, null, 2);
}

// ---------------------------------------------------------------------------
// Conditions.

const OPERATORS = [
  "StringEquals",
  "StringNotEquals",
  "StringLike",
  "StringNotLike",
  "StringEqualsIgnoreCase",
  "ArnEquals",
  "ArnLike",
  "ArnNotLike",
  "Bool",
  "IpAddress",
  "NotIpAddress",
  "NumericLessThan",
  "NumericLessThanEquals",
  "NumericGreaterThan",
  "DateGreaterThan",
  "DateLessThan",
  "Null",
  "ForAnyValue:StringEquals",
  "ForAllValues:StringEquals",
  "ForAnyValue:StringLike",
];

const CONDITION_KEYS = [
  "aws:SourceIp",
  "aws:SourceVpc",
  "aws:SourceVpce",
  "aws:SourceArn",
  "aws:SourceAccount",
  "aws:PrincipalArn",
  "aws:PrincipalAccount",
  "aws:PrincipalOrgID",
  "aws:PrincipalTag/team",
  "aws:ResourceTag/team",
  "aws:RequestTag/team",
  "aws:TagKeys",
  "aws:RequestedRegion",
  "aws:SecureTransport",
  "aws:MultiFactorAuthPresent",
  "aws:MultiFactorAuthAge",
  "aws:CurrentTime",
  "aws:CalledVia",
  "aws:ViaAWSService",
  "aws:userid",
  "aws:username",
  "s3:prefix",
  "s3:x-amz-server-side-encryption",
  "s3:x-amz-acl",
  "kms:ViaService",
  "kms:EncryptionContext:aws:arn",
  "iam:PassedToService",
  "iam:PermissionsBoundary",
  "sts:ExternalId",
  "sts:RoleSessionName",
  "token.actions.githubusercontent.com:sub",
  "token.actions.githubusercontent.com:aud",
  "ec2:ResourceTag/Name",
  "lambda:FunctionArn",
];

/** One-click condition helpers: a label and the condition they add. */
const CONDITION_PRESETS: { id: string; label: string; cond: Condition }[] = [
  { id: "mfa", label: "Require MFA", cond: { op: "Bool", key: "aws:MultiFactorAuthPresent", values: ["true"] } },
  { id: "tls", label: "Only over TLS", cond: { op: "Bool", key: "aws:SecureTransport", values: ["true"] } },
  { id: "ip", label: "From these IPs", cond: { op: "IpAddress", key: "aws:SourceIp", values: ["203.0.113.0/24"] } },
  { id: "region", label: "In these Regions", cond: { op: "StringEquals", key: "aws:RequestedRegion", values: ["us-east-1"] } },
  { id: "org", label: "My organization only", cond: { op: "StringEquals", key: "aws:PrincipalOrgID", values: ["o-exampleorgid"] } },
  { id: "abac", label: "Matching team tag", cond: { op: "StringEquals", key: "aws:ResourceTag/team", values: ["${aws:PrincipalTag/team}"] } },
  { id: "source", label: "From this source ARN", cond: { op: "ArnLike", key: "aws:SourceArn", values: ["arn:aws:"] } },
  { id: "account", label: "From this account", cond: { op: "StringEquals", key: "aws:SourceAccount", values: ["123456789012"] } },
];

/** Whole statements people add often. */
const STATEMENT_SNIPPETS: { id: string; label: string; kinds: PolicyKind[]; make: () => Omit<Statement, "uid"> }[] = [
  {
    id: "deny-insecure",
    label: "Deny insecure transport",
    kinds: ["identity", "resource"],
    make: () => ({ sid: "DenyInsecureTransport", effect: "Deny", actions: ["*"], resources: ["*"], principals: [{ type: "*", values: [] }], conditions: [{ op: "Bool", key: "aws:SecureTransport", values: ["false"] }] }),
  },
  {
    id: "deny-regions",
    label: "Deny other Regions",
    kinds: ["identity"],
    make: () => ({ sid: "DenyOutsideRegions", effect: "Deny", actions: ["*"], resources: ["*"], principals: [], conditions: [{ op: "StringNotEquals", key: "aws:RequestedRegion", values: ["us-east-1", "us-west-2"] }] }),
  },
  {
    id: "deny-no-mfa",
    label: "Deny without MFA",
    kinds: ["identity"],
    make: () => ({ sid: "DenyWithoutMFA", effect: "Deny", actions: ["*"], resources: ["*"], principals: [], conditions: [{ op: "BoolIfExists", key: "aws:MultiFactorAuthPresent", values: ["false"] }] }),
  },
  {
    id: "pass-role",
    label: "Pass a role to a service",
    kinds: ["identity"],
    make: () => ({ sid: "PassRole", effect: "Allow", actions: ["iam:PassRole"], resources: ["*"], principals: [], conditions: [{ op: "StringEquals", key: "iam:PassedToService", values: ["lambda.amazonaws.com"] }] }),
  },
  {
    id: "assume",
    label: "Assume another role",
    kinds: ["identity"],
    make: () => ({ sid: "AssumeRole", effect: "Allow", actions: ["sts:AssumeRole"], resources: ["arn:aws:iam::123456789012:role/"], principals: [], conditions: [] }),
  },
  {
    id: "external-id",
    label: "Another account, with external ID",
    kinds: ["trust"],
    make: () => ({ sid: "", effect: "Allow", actions: ["sts:AssumeRole"], resources: [], principals: [{ type: "AWS", values: ["arn:aws:iam::123456789012:root"] }], conditions: [{ op: "StringEquals", key: "sts:ExternalId", values: ["unique-external-id"] }] }),
  },
  {
    id: "github",
    label: "GitHub Actions",
    kinds: ["trust"],
    make: () => ({
      sid: "GitHubActions",
      effect: "Allow",
      actions: ["sts:AssumeRoleWithWebIdentity"],
      resources: [],
      principals: [{ type: "Federated", values: ["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"] }],
      conditions: [
        { op: "StringEquals", key: "token.actions.githubusercontent.com:aud", values: ["sts.amazonaws.com"] },
        { op: "StringLike", key: "token.actions.githubusercontent.com:sub", values: ["repo:OWNER/REPO:*"] },
      ],
    }),
  },
];

// ---------------------------------------------------------------------------
// Small pieces.

function Chips({ values, remove, mono = true, icon, levels }: { values: string[]; remove: (v: string) => void; mono?: boolean; icon?: (v: string) => string | undefined; levels?: boolean }) {
  if (!values.length) return null;
  return (
    <span className="policy-chips">
      {values.map((v) => {
        const i = icon?.(v);
        return (
          <span key={v} className="policy-chip" data-level={levels && v.includes(":") ? accessLevel(v) : undefined} title={v}>
            {i && <img src={iconUrl(i)} alt="" width={14} height={14} />}
            <span className={mono ? "mono" : undefined}>{v}</span>
            <button type="button" aria-label={`Remove ${v}`} onClick={() => remove(v)}>
              <X size={12} aria-hidden />
            </button>
          </span>
        );
      })}
    </span>
  );
}

function ActionSearch({ add, kind, services }: { add: (actions: string[]) => void; kind: PolicyKind; services: string[] }) {
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const hits = useMemo(() => {
    if (kind === "trust") {
      const all = ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML", "sts:TagSession", "sts:SetSourceIdentity"];
      return all.filter((a) => a.toLowerCase().includes(q.toLowerCase()));
    }
    return searchActions(q);
  }, [q, kind]);
  useEffect(() => setActive(0), [q]);
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (hits.length) setActive((a) => (a + (e.key === "ArrowDown" ? 1 : -1) + hits.length) % hits.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const typed = q.trim();
      const v = hits[active] ?? (/^[\w-]+:[\w*]+$/.test(typed) || typed === "*" ? typed : "");
      if (v) {
        add([v]);
        setQ("");
      }
    } else if (e.key === "Escape" && q) {
      e.preventDefault();
      e.stopPropagation();
      setQ("");
    }
  };
  // The service the search or the chosen actions are about, for the bulk buttons.
  const prefix = (q.includes(":") ? q.split(":")[0] : ALL_ACTIONS[q.trim().toLowerCase()] ? q.trim().toLowerCase() : services[0]) ?? "";
  const levels = prefix && ALL_ACTIONS[prefix] ? (["List", "Read", "Write"] as const) : [];
  return (
    <div className="policy-search">
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onKeyDown={onKey}
        placeholder={kind === "trust" ? "sts:AssumeRole" : "Search actions: s3 get, sqs:Send, kms…"}
        aria-label="Add actions"
        spellCheck={false}
        autoComplete="off"
      />
      {(levels.length > 0 || kind !== "trust") && !q && prefix && (
        <span className="policy-bulk">
          <img src={iconUrl(serviceIcon(prefix))} alt="" width={14} height={14} />
          {levels.map((l) => (
            <button key={l} type="button" className="repair" onClick={() => add(ALL_ACTIONS[prefix].filter((a) => accessLevel(a) === l).map((a) => `${prefix}:${a}`))}>
              All {l.toLowerCase()}
            </button>
          ))}
          <button type="button" className="repair" onClick={() => add([`${prefix}:*`])}>
            {prefix}:*
          </button>
        </span>
      )}
      {q && hits.length > 0 && (
        <div className="policy-hits" role="listbox" aria-label="Matching actions">
          {hits.map((h, i) => (
            <button
              key={h}
              type="button"
              role="option"
              aria-selected={i === active}
              data-active={i === active ? "" : undefined}
              onMouseEnter={() => setActive(i)}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => {
                add([h]);
                setQ("");
              }}
            >
              <img src={iconUrl(serviceIcon(h.split(":")[0]))} alt="" width={16} height={16} />
              <span className="mono">{h}</span>
              <span className="policy-level">{accessLevel(h)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

const PRINCIPAL_TYPES: { id: PrincipalType; label: string }[] = [
  { id: "Service", label: "AWS service" },
  { id: "AWS", label: "AWS account or principal" },
  { id: "Federated", label: "Identity provider" },
  { id: "*", label: "Everyone" },
];

const SERVICE_PRINCIPALS = [
  "lambda.amazonaws.com",
  "ec2.amazonaws.com",
  "ecs-tasks.amazonaws.com",
  "eks.amazonaws.com",
  "events.amazonaws.com",
  "scheduler.amazonaws.com",
  "states.amazonaws.com",
  "firehose.amazonaws.com",
  "sns.amazonaws.com",
  "s3.amazonaws.com",
  "logs.amazonaws.com",
  "cloudtrail.amazonaws.com",
  "cloudformation.amazonaws.com",
  "codebuild.amazonaws.com",
  "apigateway.amazonaws.com",
  "bedrock.amazonaws.com",
  "amplify.amazonaws.com",
  "ses.amazonaws.com",
  "imagebuilder.amazonaws.com",
  "autoscaling.amazonaws.com",
  "elasticloadbalancing.amazonaws.com",
  "guardduty.amazonaws.com",
  "delivery.logs.amazonaws.com",
];

function Principals({ value, change }: { value: Statement["principals"]; change: (p: Statement["principals"]) => void }) {
  const [type, setType] = useState<PrincipalType>(value[0]?.type ?? "Service");
  const [draft, setDraft] = useState("");
  const everyone = value.some((p) => p.type === "*");
  const add = (v: string) => {
    const t = type;
    if (t === "*") return change([{ type: "*", values: [] }]);
    const val = t === "AWS" && /^\d{12}$/.test(v) ? `arn:aws:iam::${v}:root` : t === "Service" && /^[a-z0-9-]+$/.test(v) ? `${v}.amazonaws.com` : v;
    if (!val) return;
    const rest = value.filter((p) => p.type !== "*");
    const existing = rest.find((p) => p.type === t);
    change(existing ? rest.map((p) => (p === existing ? { ...p, values: [...new Set([...p.values, val])] } : p)) : [...rest, { type: t, values: [val] }]);
    setDraft("");
  };
  const all = value.flatMap((p) => p.values.map((v) => ({ t: p.type, v })));
  return (
    <div className="policy-row">
      <span className="policy-row-label">Principal</span>
      <div className="policy-row-body">
        {everyone ? (
          <Chips values={["* (everyone)"]} mono={false} remove={() => change([])} />
        ) : (
          <Chips values={all.map((a) => a.v)} remove={(v) => change(value.map((p) => ({ ...p, values: p.values.filter((x) => x !== v) })).filter((p) => p.values.length))} />
        )}
        <span className="policy-inline">
          <select value={type} onChange={(e) => setType(e.target.value as PrincipalType)} aria-label="Principal type">
            {PRINCIPAL_TYPES.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label}
              </option>
            ))}
          </select>
          {type === "*" ? (
            <button type="button" className="repair" onClick={() => add("*")}>
              Allow everyone
            </button>
          ) : type === "AWS" ? (
            <span className="policy-grow">
              <ResourcePicker kind={["iam-role", "iam-user"]} name="" value={draft} onValueChange={(v, o) => (o ? add(v) : setDraft(v))} placeholder="Account ID, role or user ARN" aria-label="AWS principal" create={false} />
            </span>
          ) : (
            <input
              className="policy-grow"
              value={draft}
              list={type === "Service" ? "policy-service-principals" : undefined}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  add(draft.trim());
                }
              }}
              placeholder={type === "Service" ? "lambda.amazonaws.com" : "arn:aws:iam::123456789012:oidc-provider/…"}
              aria-label="Principal"
              spellCheck={false}
            />
          )}
          {type !== "*" && (
            <button type="button" className="icon-button plain" aria-label="Add principal" title="Add principal" onClick={() => add(draft.trim())}>
              <Plus size={16} aria-hidden />
            </button>
          )}
        </span>
        <datalist id="policy-service-principals">
          {SERVICE_PRINCIPALS.map((p) => (
            <option key={p} value={p} />
          ))}
        </datalist>
      </div>
    </div>
  );
}

function Resources({ value, change, services }: { value: string[]; change: (r: string[]) => void; services: string[] }) {
  const kinds = [...new Set(services.map((s) => RESOURCE_FOR[s]).filter(Boolean))] as ResourceKind[];
  const [draft, setDraft] = useState("");
  const add = (arns: string[]) => {
    const next = [...new Set([...value.filter((v) => v !== "*"), ...arns.filter(Boolean)])];
    change(next);
    setDraft("");
  };
  const all = value.length === 0 || value.includes("*");
  return (
    <div className="policy-row">
      <span className="policy-row-label">Resources</span>
      <div className="policy-row-body">
        <span className="policy-inline">
          <span className="segments-mini" role="group" aria-label="Resources">
            <button type="button" aria-pressed={all} onClick={() => change(["*"])}>
              All
            </button>
            <button type="button" aria-pressed={!all} onClick={() => !all || change([])}>
              Specific
            </button>
          </span>
        </span>
        {!all || value.length === 0 ? null : null}
        {!all && <Chips values={value} remove={(v) => change(value.filter((x) => x !== v))} />}
        {(!all || value.length === 0) && value[0] !== "*" ? (
          <span className="policy-inline">
            <span className="policy-grow">
              {kinds.length ? (
                <ResourcePicker
                  kind={kinds}
                  use="arn"
                  name=""
                  value={draft}
                  create={false}
                  aria-label="Add a resource"
                  placeholder="Search resources or paste an ARN"
                  onValueChange={(v, o) => {
                    if (!o) return setDraft(v);
                    // A bucket's actions are on the bucket and on its objects.
                    add(o.kind === "s3-bucket" ? [v, `${v}/*`] : [v]);
                  }}
                />
              ) : (
                <input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="arn:aws:…" aria-label="Add a resource" spellCheck={false} onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), add([draft.trim()]))} />
              )}
            </span>
            <button type="button" className="icon-button plain" aria-label="Add resource" title="Add resource" onClick={() => add([draft.trim()])}>
              <Plus size={16} aria-hidden />
            </button>
          </span>
        ) : null}
      </div>
    </div>
  );
}

function Conditions({ value, change }: { value: Condition[]; change: (c: Condition[]) => void }) {
  // The helpers show on an empty statement; once it has a condition they wait behind one button.
  const [open, setOpen] = useState(value.length === 0);
  const set = (i: number, c: Partial<Condition>) => change(value.map((x, j) => (j === i ? { ...x, ...c } : x)));
  return (
    <div className="policy-row">
      <span className="policy-row-label">Conditions</span>
      <div className="policy-row-body">
        {value.map((c, i) => (
          <span key={i} className="policy-condition">
            <input list="policy-condition-keys" value={c.key} onChange={(e) => set(i, { key: e.target.value })} aria-label="Condition key" placeholder="aws:SourceIp" spellCheck={false} />
            <select value={c.op} onChange={(e) => set(i, { op: e.target.value })} aria-label="Operator">
              {[...new Set([c.op, ...OPERATORS])].map((o) => (
                <option key={o}>{o}</option>
              ))}
            </select>
            <input value={c.values.join(", ")} onChange={(e) => set(i, { values: e.target.value.split(",").map((v) => v.trim()).filter((v, k, a) => v || k === a.length - 1) })} aria-label="Values" placeholder="value, value" spellCheck={false} />
            <button type="button" className="icon-button plain" aria-label="Remove condition" title="Remove condition" onClick={() => change(value.filter((_, j) => j !== i))}>
              <X size={14} aria-hidden />
            </button>
          </span>
        ))}
        {!open ? (
          <span className="repairs">
            <button type="button" className="repair" onClick={() => setOpen(true)}>
              <Plus size={12} aria-hidden /> Condition
            </button>
          </span>
        ) : (
        <span className="repairs">
          {CONDITION_PRESETS.filter((p) => !value.some((c) => c.key === p.cond.key)).map((p) => (
            <button key={p.id} type="button" className="repair" data-kind="suggest" onClick={() => {
                change([...value, { ...p.cond, values: [...p.cond.values] }]);
                setOpen(false);
              }}>
              <Plus size={12} aria-hidden /> {p.label}
            </button>
          ))}
          <button type="button" className="repair" onClick={() => change([...value, { op: "StringEquals", key: "", values: [""] }])}>
            <Plus size={12} aria-hidden /> Other
          </button>
        </span>
        )}
        <datalist id="policy-condition-keys">
          {CONDITION_KEYS.map((k) => (
            <option key={k} value={k} />
          ))}
        </datalist>
      </div>
    </div>
  );
}

function StatementCard({ s, kind, change, remove, only }: { s: Statement; kind: PolicyKind; change: (s: Statement) => void; remove: () => void; only: boolean }) {
  const services = [...new Set(s.actions.map((a) => a.split(":")[0]).filter((p) => p && p !== "*"))];
  if (s.raw) {
    return (
      <div className="policy-statement" data-effect={s.effect}>
        <div className="policy-statement-head">
          <span className="policy-effect-static">{s.effect}</span>
          <span className="policy-sid">{s.sid || "Statement"}</span>
          <span className="field-hint">Uses keys the builder does not edit; change it in JSON.</span>
          {!only && (
            <button type="button" className="icon-button plain" aria-label="Remove statement" title="Remove statement" onClick={remove}>
              <Trash2 size={15} aria-hidden />
            </button>
          )}
        </div>
      </div>
    );
  }
  return (
    <div className="policy-statement" data-effect={s.effect}>
      <div className="policy-statement-head">
        <span className="segments-mini" role="radiogroup" aria-label="Effect">
          {(["Allow", "Deny"] as const).map((e) => (
            <button key={e} type="button" role="radio" aria-checked={s.effect === e} aria-pressed={s.effect === e} data-effect={e} onClick={() => change({ ...s, effect: e })}>
              {e}
            </button>
          ))}
        </span>
        <input className="policy-sid" value={s.sid} onChange={(e) => change({ ...s, sid: e.target.value.replace(/[^A-Za-z0-9]/g, "") })} placeholder="Statement ID (optional)" aria-label="Statement ID" spellCheck={false} />
        {!only && (
          <button type="button" className="icon-button plain" aria-label="Remove statement" title="Remove statement" onClick={remove}>
            <Trash2 size={15} aria-hidden />
          </button>
        )}
      </div>
      {kind !== "identity" && <Principals value={s.principals} change={(principals) => change({ ...s, principals })} />}
      <div className="policy-row">
        <span className="policy-row-label">Actions</span>
        <div className="policy-row-body">
          <Chips levels values={s.actions} remove={(v) => change({ ...s, actions: s.actions.filter((a) => a !== v) })} icon={(v) => (v.includes(":") ? serviceIcon(v.split(":")[0]) : undefined)} />
          <ActionSearch kind={kind} services={services} add={(a) => change({ ...s, actions: [...new Set([...s.actions, ...a])] })} />
        </div>
      </div>
      {kind !== "trust" && <Resources value={s.resources} services={services} change={(resources) => change({ ...s, resources })} />}
      <Conditions value={s.conditions} change={(conditions) => change({ ...s, conditions })} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// The assistant: describe the access, get statements.

const EXAMPLES: Record<PolicyKind, string> = {
  identity: "Read the reports bucket, send to the jobs queue, write logs, require MFA",
  resource: "Let account 123456789012 read objects, only over TLS",
  trust: "Lambda and ECS tasks, or GitHub repo owner/app on main",
};

export function PolicyAssistant({ kind, add }: { kind: PolicyKind; add: (statements: DraftStatement[]) => void }) {
  const [text, setText] = useState("");
  const kinds = useMemo(() => kindsIn(text), [text]);
  const { items } = useResources(kinds, kinds.length > 0);
  const draft = useMemo(() => (text.trim().length > 2 ? draftPolicy(text, kind, items ?? []) : null), [text, kind, items]);
  const apply = () => {
    if (!draft?.statements.length) return;
    add(draft.statements);
    setText("");
  };
  return (
    <div className="policy-assistant">
      <span className="policy-assistant-input">
        <Sparkles size={15} aria-hidden />
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              apply();
            }
          }}
          placeholder={EXAMPLES[kind]}
          aria-label="Describe the access"
          spellCheck={false}
          autoComplete="off"
          data-testid="policy-assistant"
        />
        {draft && draft.statements.length > 0 && (
          <button type="button" className="repair" data-kind="generate" onClick={apply} data-testid="policy-assistant-apply">
            <Plus size={12} aria-hidden /> {draft.statements.length === 1 ? "Add statement" : `Add ${draft.statements.length} statements`}
          </button>
        )}
      </span>
      {draft && (
        <span className="policy-notes" aria-live="polite">
          {draft.notes.length ? draft.notes.map((n) => <span key={n}>{n}</span>) : <span className="field-hint">Name a service and what to do with it: read, write, send, invoke…</span>}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// The editor.

export type PolicyKind = "identity" | "resource" | "trust";

export function PolicyEditor({
  label,
  name,
  defaultValue,
  kind = "identity",
  rows = 12,
  required,
  hint,
  testId,
  startIn,
  "aria-label": ariaLabel,
  ...rules
}: FieldRules & {
  "aria-label"?: string;
  label: string;
  name: string;
  defaultValue?: string;
  kind?: PolicyKind;
  rows?: number;
  required?: boolean;
  hint?: ReactNode;
  testId?: string;
  /** Open on the builder or the JSON (default: the builder when the document parses). */
  startIn?: "visual" | "json";
}) {
  const area = useRef<HTMLTextAreaElement>(null);
  const initial = useMemo(() => parse(defaultValue ?? ""), [defaultValue]);
  const [mode, setMode] = useState<"visual" | "json">(startIn ?? (initial && (defaultValue ?? "").trim() ? "visual" : "json"));
  const [doc, setDoc] = useState(() => initial ?? { version: "2012-10-17", statements: [] });
  const [problem, setProblem] = useState<string | null>(null);
  // Untouched, the starting document is only a template: a drafted policy replaces it.
  const touched = useRef(false);

  const write = useCallback(
    (next: { version: string; statements: Statement[] }) => {
      touched.current = true;
      setDoc(next);
      if (area.current) setControlValue(area.current, serialize(next.version, next.statements, kind));
    },
    [kind],
  );

  const toVisual = () => {
    const parsed = parse(area.current?.value ?? "");
    if (!parsed) {
      setProblem("The JSON does not parse yet; fix it to use the builder.");
      return;
    }
    setProblem(null);
    setDoc(parsed);
    setMode("visual");
  };

  const blank = (): Statement => ({
    uid: ++uid,
    sid: "",
    effect: "Allow",
    actions: kind === "trust" ? ["sts:AssumeRole"] : [],
    resources: kind === "trust" ? [] : ["*"],
    principals: kind === "identity" ? [] : [{ type: "Service", values: [] }],
    conditions: [],
  });

  const statements = doc.statements;
  return (
    <div className="policy-editor" data-mode={mode} data-testid={testId}>
      <div className="policy-head">
        <span className="field-label">{label}</span>
        <span className="segments-mini" role="tablist" aria-label="Editor">
          <button type="button" role="tab" aria-selected={mode === "visual"} aria-pressed={mode === "visual"} onClick={toVisual} title="Visual editor">
            <LayoutList size={14} aria-hidden /> Visual
          </button>
          <button type="button" role="tab" aria-selected={mode === "json"} aria-pressed={mode === "json"} onClick={() => setMode("json")} title="JSON">
            <Braces size={14} aria-hidden /> JSON
          </button>
        </span>
      </div>
      {problem && mode === "json" && <span className="field-issue">{problem}</span>}
      {mode === "visual" && (
        <div className="policy-statements">
          <PolicyAssistant
            kind={kind}
            add={(drafted) => {
              const kept = touched.current ? statements.filter((s) => s.actions.length || s.raw) : [];
              write({ ...doc, statements: [...kept, ...drafted.map((d) => ({ ...d, uid: ++uid }))] });
            }}
          />
          {statements.map((s, i) => (
            <StatementCard
              key={s.uid}
              s={s}
              kind={kind}
              only={statements.length === 1}
              change={(n) => write({ ...doc, statements: statements.map((x, j) => (j === i ? n : x)) })}
              remove={() => write({ ...doc, statements: statements.filter((_, j) => j !== i) })}
            />
          ))}
          <span className="policy-add">
            <button type="button" className="repair" onClick={() => write({ ...doc, statements: [...statements, blank()] })}>
              <Plus size={14} aria-hidden /> Statement
            </button>
            {STATEMENT_SNIPPETS.filter((x) => x.kinds.includes(kind)).map((x) => (
              <button key={x.id} type="button" className="repair" data-kind="suggest" onClick={() => write({ ...doc, statements: [...statements.filter((s) => s.actions.length || s.raw), { ...x.make(), uid: ++uid }] })}>
                <Plus size={12} aria-hidden /> {x.label}
              </button>
            ))}
          </span>
        </div>
      )}
      <FieldShell label={label} hint={mode === "json" ? hint : undefined} {...rules}>
        <textarea
          ref={area}
          name={name}
          rows={rows}
          required={required}
          aria-label={ariaLabel ?? label}
          className={mode === "json" ? "code-editor" : "code-editor policy-json-hidden"}
          spellCheck={false}
          defaultValue={defaultValue}
          tabIndex={mode === "json" ? undefined : -1}
          onInvalid={() => setMode("json")}
        />
      </FieldShell>
    </div>
  );
}
