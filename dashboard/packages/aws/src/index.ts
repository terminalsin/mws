// Server-only helpers shared by every service package. Pages talk to MWS exactly as an
// application would: through the AWS SDK for JavaScript v3, pointed at the
// MWS endpoint with the credentials below. The only non-AWS calls go to MWS's
// own control API (`/_mws/...`) and the outboxes services expose under
// `/_aws/...`.
import "server-only";

import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import type { ActionResult, FrameInfo } from "@mws-dashboard/ui";
import { REGION_COOKIE } from "@mws-dashboard/ui/constants";
import { CONFLICT, memberPath, parseServerIssues, type FieldIssue, type IssueCode, type Repair, type Rule } from "@mws-dashboard/ui/validation";
import { revalidatePath } from "next/cache";
import { cookies } from "next/headers";
import { unstable_rethrow } from "next/navigation";

export type { ActionResult };

export function endpoint(): string {
  return (process.env.MWS_ENDPOINT ?? "http://127.0.0.1:4566").replace(/\/$/, "");
}

export function credentials() {
  return {
    accessKeyId: process.env.MWS_ACCESS_KEY_ID ?? "AKIAMWSROOTEXAMPLE00",
    secretAccessKey: process.env.MWS_SECRET_ACCESS_KEY ?? "mwsRootSecretAccessKeyEXAMPLEKEY00000000",
    ...(process.env.MWS_SESSION_TOKEN ? { sessionToken: process.env.MWS_SESSION_TOKEN } : {}),
  };
}

/** The region the user picked in the top bar (one cookie for the whole console). */
export async function region(): Promise<string> {
  const jar = await cookies();
  return jar.get(REGION_COOKIE)?.value || process.env.MWS_REGION || "us-east-1";
}

export interface ClientSettings {
  endpoint: string;
  region: string;
  credentials: ReturnType<typeof credentials>;
  maxAttempts: number;
}

/** Build an SDK v3 client for the selected region, pointed at MWS:
 * `await client(S3Client, { forcePathStyle: true })`. */
export async function client<C, E extends object = object>(
  Client: new (config: ClientSettings & E) => C,
  extra?: E,
): Promise<C> {
  const settings: ClientSettings = { endpoint: endpoint(), region: await region(), credentials: credentials(), maxAttempts: 1 };
  return new Client({ ...settings, ...(extra ?? ({} as E)) });
}

/** "Name: message" for SDK errors, the message for anything else. */
export function describeError(e: unknown): string {
  if (e instanceof Error) {
    const name = e.name && e.name !== "Error" ? `${e.name}: ` : "";
    return name + (e.message || "request failed");
  }
  return String(e);
}

export type Loaded<T> = { ok: true; value: T } | { ok: false; error: string };

/** Run a read for a page, turning a failure into a message to show instead
 * of an error page (an AccessDenied should not hide the rest of the page). */
export async function load<T>(read: () => Promise<T>): Promise<Loaded<T>> {
  try {
    return { ok: true, value: await read() };
  } catch (e) {
    unstable_rethrow(e);
    return { ok: false, error: describeError(e) };
  }
}

/** A problem with one form field, thrown from an action: it shows on that
 * field (with repairs) instead of under the form. `rule` is the constraint
 * the value broke, so the field's repairs can fix it (e.g. `{ max: 6 }`). */
export class FieldError extends Error {
  constructor(
    readonly field: string,
    message: string,
    readonly code: IssueCode = "server",
    readonly rule?: Rule,
    /** Repairs only the action can work out (from what the value refers to). */
    readonly repairs?: Repair[],
  ) {
    super(message);
    this.name = "FieldError";
  }
}

export interface ActOptions {
  /** Paths to revalidate after success. */
  revalidate?: string[];
  /** Form field names by API member (`QueueName: "name"`) or by error code
   * (`QueueNameExists: "name"`, `NoSuchEntityException: "role"`, as the SDK names it), for errors that
   * name a member the form calls differently, or name none. */
  fields?: Record<string, string>;
}

/** Wrap a server action body: a returned string is the success message, an
 * exception becomes an error result (with the fields it concerns, see
 * `fieldIssues`), and `revalidate` paths are refreshed:
 * `act(run, "/sqs")` or `act(run, { revalidate: ["/sqs"], fields: {...} })`. */
export async function act(
  run: () => Promise<string | ActionResult>,
  ...revalidate: (string | ActOptions)[]
): Promise<ActionResult> {
  const options = revalidate.filter((r): r is ActOptions => typeof r === "object");
  const paths = [...revalidate.filter((r): r is string => typeof r === "string"), ...options.flatMap((o) => o.revalidate ?? [])];
  const fields = Object.assign({}, ...options.map((o) => o.fields ?? {})) as Record<string, string>;
  try {
    const out = await run();
    for (const path of paths) revalidatePath(path, "page");
    return typeof out === "string" ? { ok: true, message: out } : out;
  } catch (e) {
    unstable_rethrow(e);
    const issues = fieldIssues(e, fields);
    return { ok: false, message: describeError(e), ...(issues.length ? { issues } : {}) };
  }
}

/** The fields an error concerns: a `FieldError`, the members an AWS
 * validation message names (with the constraint each broke, so the field
 * can repair the value), an "already exists" error (lands on the form's
 * `unique` field), or anything `fields` maps by member or error code. */
export function fieldIssues(e: unknown, fields: Record<string, string> = {}): FieldIssue[] {
  if (e instanceof FieldError)
    return [{ field: e.field, code: e.code, message: e.message, ...(e.rule ? { rule: e.rule } : {}), ...(e.repairs?.length ? { repairs: e.repairs } : {}) }];
  if (!(e instanceof Error)) return [];
  const byMember = (member: string) => {
    const path = memberPath(member).join(".");
    const key = Object.keys(fields).find((k) => memberPath(k).join(".") === path);
    return key ? fields[key] : undefined;
  };
  const parsed = parseServerIssues(e.message).map((i) => ({ ...i, field: i.member ? byMember(i.member) : undefined }));
  if (parsed.length) return parsed;
  // "The value supplied for parameter 'scheduleExpression' is not valid."
  const named = e.message.match(/\bparameter '([\w.]+)'/)?.[1];
  if (named) return [{ field: byMember(named), member: named, code: "server", message: e.message }];
  const field = fields[e.name];
  if (CONFLICT.test(e.name)) return [{ field, code: "taken", message: "Already exists" }];
  if (field) return [{ field, code: /NotFound|NoSuch/i.test(e.name) ? "missing" : "server", message: e.message || e.name }];
  return [];
}

export function text(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value.trim() : "";
}

export function required(form: FormData, name: string, label = name): string {
  const value = text(form, name);
  if (!value) throw new FieldError(name, `${label} is required`, "required");
  return value;
}

export async function frameInfo(): Promise<FrameInfo> {
  const r = await region();
  try {
    const sts = await client(STSClient);
    const me = await sts.send(new GetCallerIdentityCommand({}));
    return { endpoint: endpoint(), region: r, account: me.Account ?? null, principal: me.Arn ?? null, error: null };
  } catch (e) {
    return { endpoint: endpoint(), region: r, account: null, principal: null, error: describeError(e) };
  }
}

/** A call to MWS's own control API or a service's `/_aws` side channel. */
export async function mws<T = unknown>(path: string, init?: RequestInit & { json?: unknown }): Promise<T> {
  const { json, ...rest } = init ?? {};
  const response = await fetch(endpoint() + path, {
    cache: "no-store",
    ...rest,
    ...(json !== undefined
      ? { body: JSON.stringify(json), headers: { "content-type": "application/json", ...(rest.headers ?? {}) } }
      : {}),
  });
  const body = await response.text();
  if (!response.ok) {
    let message = body;
    try {
      const parsed = JSON.parse(body);
      message = parsed.error ?? parsed.message ?? body;
    } catch {
      // plain text
    }
    throw new Error(`${path} answered ${response.status}: ${message}`);
  }
  return (body ? JSON.parse(body) : undefined) as T;
}

export function bytes(n: number | undefined | null): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export function when(d: Date | string | number | undefined | null): string {
  if (d == null || d === "") return "—";
  const date = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(date.getTime())) return String(d);
  return date.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

/** The last segment of an ARN-ish identifier. */
export function shortName(arn: string | undefined): string {
  if (!arn) return "";
  return arn.split(/[:/]/).pop() ?? arn;
}

/** Up to `limit` items from a paginated list call. */
export async function collect<T, R>(
  page: (token: string | undefined) => Promise<R>,
  items: (r: R) => T[] | undefined,
  next: (r: R) => string | undefined,
  limit = 1000,
): Promise<T[]> {
  const out: T[] = [];
  let token: string | undefined;
  do {
    const r = await page(token);
    out.push(...(items(r) ?? []));
    token = next(r);
  } while (token && out.length < limit);
  return out.slice(0, limit);
}

/** Every item of a paginated list call (up to `limit`, 10,000 by default):
 * `all((NextToken) => c.send(new ListXCommand({ NextToken })), (r) => r.Items, (r) => r.NextToken)`.
 * Use it wherever a count, a summary or a lookup needs the whole list. */
export function all<T, R>(
  page: (token: string | undefined) => Promise<R>,
  items: (r: R) => T[] | undefined,
  next: (r: R) => string | undefined,
  limit = 10_000,
): Promise<T[]> {
  return collect(page, items, next, limit);
}

/** Batch calls answer 200 with per-item failures (`failures`,
 * `failedVersions`, `Failed`, `UnprocessedItems`...): throw when there are
 * any, so the form reports the failure instead of a false success.
 * `checkFailures(r.failures, (f) => `${f.imageId?.imageTag}: ${f.failureReason}`)`. */
export function checkFailures<F>(failures: F[] | Record<string, F> | undefined | null, describe: (f: F, key?: string) => string): void {
  if (!failures) return;
  const list = Array.isArray(failures) ? failures.map((f) => describe(f)) : Object.entries(failures).map(([k, f]) => describe(f, k));
  if (list.length) throw new Error(list.length === 1 ? list[0] : `${list.length} failed: ${list.slice(0, 5).join("; ")}${list.length > 5 ? "; ..." : ""}`);
}

/** "3m ago", "2d ago", "in 4h": for timestamps where the gist is enough. */
export function ago(d: Date | string | number | undefined | null): string {
  if (d == null || d === "") return "—";
  const date = d instanceof Date ? d : new Date(typeof d === "number" && d < 1e12 ? d * 1000 : d);
  const t = date.getTime();
  if (Number.isNaN(t)) return String(d);
  const s = Math.round((Date.now() - t) / 1000);
  const abs = Math.abs(s);
  const [n, unit] =
    abs < 60 ? [abs, "s"] : abs < 3600 ? [Math.round(abs / 60), "m"] : abs < 86400 ? [Math.round(abs / 3600), "h"] : abs < 86400 * 365 ? [Math.round(abs / 86400), "d"] : [Math.round(abs / (86400 * 365)), "y"];
  if (abs < 5) return "now";
  return s >= 0 ? `${n}${unit} ago` : `in ${n}${unit}`;
}

/** A resource as the console's search and home page see it. Each service
 * package lists its own in `services/<id>/inventory.ts`. */
export interface InventoryItem {
  /** Catalog service id ("s3", "sqs", ...). */
  service: string;
  /** The resource type, in AWS's words ("Bucket", "Queue"). */
  type: string;
  /** Unique across the console: usually the ARN. */
  id: string;
  name: string;
  /** Absolute path of the resource's page. */
  href: string;
  /** A short fact worth showing next to the name. */
  detail?: string;
  tags?: Record<string, string>;
  /** Something that needs attention: an alarm firing, a backlog, a deletion. */
  signal?: { tone: "bad" | "warn"; text: string };
}

/** AWS tag lists ([{Key, Value}]) as a plain object. */
export function tagMap(tags: { Key?: string; Value?: string }[] | Record<string, string> | undefined | null): Record<string, string> {
  if (!tags) return {};
  if (!Array.isArray(tags)) return tags;
  return Object.fromEntries(tags.filter((t) => t.Key).map((t) => [t.Key!, t.Value ?? ""]));
}
