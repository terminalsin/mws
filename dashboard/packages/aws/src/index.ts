// Server-only helpers shared by every service package. Pages talk to MWS exactly as an
// application would: through the AWS SDK for JavaScript v3, pointed at the
// MWS endpoint with the credentials below. The only non-AWS calls go to MWS's
// own control API (`/_mws/...`) and the outboxes services expose under
// `/_aws/...`.
import "server-only";

import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import type { ActionResult, FrameInfo } from "@mws-dashboard/ui";
import { REGION_COOKIE } from "@mws-dashboard/ui/constants";
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

/** Wrap a server action body: a returned string is the success message, an
 * exception becomes an error result, and `revalidate` paths are refreshed. */
export async function act(
  run: () => Promise<string | ActionResult>,
  ...revalidate: string[]
): Promise<ActionResult> {
  try {
    const out = await run();
    for (const path of revalidate) revalidatePath(path, "page");
    return typeof out === "string" ? { ok: true, message: out } : out;
  } catch (e) {
    unstable_rethrow(e);
    return { ok: false, message: describeError(e) };
  }
}

export function text(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === "string" ? value.trim() : "";
}

export function required(form: FormData, name: string, label = name): string {
  const value = text(form, name);
  if (!value) throw new Error(`${label} is required`);
  return value;
}

/** Information for the shared frame: endpoint, region and who we are. */
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
