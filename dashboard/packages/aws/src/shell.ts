// The terminal and file browser of compute resources: MWS's signed
// `/_aws/ec2/instances/<id>/...` and `/_aws/ecs/tasks/<cluster>/<task>/<container>/...`
// endpoints, called with SigV4 as any AWS client would.
import "server-only";

import { createHash, createHmac } from "node:crypto";

import { credentials, describeError, endpoint, region } from "./index";

export interface ShellTarget {
  /** The signing service: `ec2` or `ecs`. */
  service: "ec2" | "ecs";
  /** The resource's endpoint path, e.g. `/_aws/ec2/instances/i-…`. */
  base: string;
}

const BASE = /^\/_aws\/(ec2\/instances\/i-[0-9a-f]+|ecs\/tasks\/[A-Za-z0-9_-]+\/[0-9a-f]+\/[A-Za-z0-9_-]+)$/;

function check(t: ShellTarget) {
  if (!BASE.test(t.base) || (t.service === "ec2") !== t.base.startsWith("/_aws/ec2/")) throw new Error("Not a console target");
}

const sha256 = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex");
const hmac = (key: string | Buffer, data: string) => createHmac("sha256", key).update(data).digest();
const enc = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** A SigV4-signed request to MWS: returns the response. */
export async function signedFetch(
  service: string,
  method: string,
  path: string,
  query: Record<string, string> = {},
  body?: Uint8Array | string,
): Promise<Response> {
  const url = new URL(endpoint() + path);
  const creds = credentials();
  const r = await region();
  const now = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  const day = now.slice(0, 8);
  const payload = body === undefined ? new Uint8Array() : typeof body === "string" ? new TextEncoder().encode(body) : body;
  const hash = sha256(payload);
  const headers: Record<string, string> = {
    host: url.host,
    "x-amz-date": now,
    "x-amz-content-sha256": hash,
  };
  if ("sessionToken" in creds && creds.sessionToken) headers["x-amz-security-token"] = creds.sessionToken as string;
  const canonicalQuery = Object.entries(query)
    .map(([k, v]) => [enc(k), enc(v)])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  const names = Object.keys(headers).sort();
  const canonical = [
    method,
    url.pathname.split("/").map(enc).join("/"),
    canonicalQuery,
    names.map((n) => `${n}:${headers[n]}\n`).join(""),
    names.join(";"),
    hash,
  ].join("\n");
  const scope = `${day}/${r}/${service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", now, scope, sha256(canonical)].join("\n");
  let key = hmac(`AWS4${creds.secretAccessKey}`, day);
  for (const part of [r, service, "aws4_request"]) key = hmac(key, part);
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  headers.authorization = `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${names.join(";")}, Signature=${signature}`;
  const { host: _host, ...send } = headers;
  return fetch(`${url.origin}${url.pathname}${canonicalQuery ? `?${canonicalQuery}` : ""}`, {
    method,
    headers: send,
    body: payload.length ? Buffer.from(payload) : undefined,
    cache: "no-store",
  });
}

async function call(t: ShellTarget, method: string, op: string, query: Record<string, string> = {}, body?: Uint8Array | string) {
  check(t);
  const res = await signedFetch(t.service, method, `${t.base}/${op}`, query, body);
  if (!res.ok) {
    const text = await res.text();
    let message = text;
    try {
      message = JSON.parse(text).message ?? text;
    } catch {
      // plain text
    }
    throw new Error(message || `${res.status}`);
  }
  return res;
}

export interface ExecResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  cwd?: string;
  error?: string;
}

export interface FileEntry {
  name: string;
  type: "file" | "dir" | "link";
  size: number;
  modified: number;
  mode: string;
}

export type Listing = { ok: true; path: string; entries: FileEntry[] } | { ok: false; error: string };
export type FileData = { ok: true; base64: string; size: number; truncated: boolean } | { ok: false; error: string };
export type Done = { ok: true } | { ok: false; error: string };

export async function exec(t: ShellTarget, command: string, cwd?: string): Promise<ExecResult> {
  try {
    const res = await call(t, "POST", "exec", {}, JSON.stringify({ command, cwd }));
    return { ok: true, ...(await res.json()) };
  } catch (e) {
    return {
      ok: false,
      stdout: "",
      stderr: "",
      exitCode: -1,
      error: describeError(e),
    };
  }
}

export async function list(t: ShellTarget, path: string): Promise<Listing> {
  try {
    return {
      ok: true,
      ...(await (await call(t, "GET", "files", { path })).json()),
    };
  } catch (e) {
    return { ok: false, error: describeError(e) };
  }
}

export async function read(t: ShellTarget, path: string): Promise<FileData> {
  try {
    const res = await call(t, "GET", "file", { path });
    const data = Buffer.from(await res.arrayBuffer());
    return {
      ok: true,
      base64: data.toString("base64"),
      size: Number(res.headers.get("x-mws-size") ?? data.length),
      truncated: res.headers.get("x-mws-truncated") === "true",
    };
  } catch (e) {
    return { ok: false, error: describeError(e) };
  }
}

export async function write(t: ShellTarget, path: string, base64: string): Promise<Done> {
  try {
    await call(t, "PUT", "file", { path }, Buffer.from(base64, "base64"));
    return { ok: true };
  } catch (e) {
    return { ok: false, error: describeError(e) };
  }
}

export async function remove(t: ShellTarget, path: string): Promise<Done> {
  try {
    await call(t, "DELETE", "file", { path });
    return { ok: true };
  } catch (e) {
    return { ok: false, error: describeError(e) };
  }
}

export async function mkdir(t: ShellTarget, path: string): Promise<Done> {
  try {
    await call(t, "POST", "dir", { path });
    return { ok: true };
  } catch (e) {
    return { ok: false, error: describeError(e) };
  }
}

export { SHELL_ACTIONS } from "./shell-bundle";
