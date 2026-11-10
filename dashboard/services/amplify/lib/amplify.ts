import "server-only";

import { endpoint } from "@mws-dashboard/aws";

/** Where a branch's site answers in a browser: `<branch>.<appId>.amplifyapp.localhost` on MWS's port. */
export function siteUrl(appId: string, branch: string): string {
  const url = new URL(endpoint());
  const host = ["127.0.0.1", "localhost", "0.0.0.0"].includes(url.hostname) ? "localhost" : url.hostname;
  return `${url.protocol}//${branch.replace(/\//g, "-")}.${appId}.amplifyapp.${host}${url.port ? `:${url.port}` : ""}/`;
}

/** Job states still on their way: the page keeps refreshing. */
export const RUNNING = /^(PENDING|PROVISIONING|RUNNING|CANCELLING|CREATED)$/;

export const envText = (env: Record<string, string> | undefined) =>
  Object.entries(env ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

export const rulesText = (rules: { source?: string; target?: string; status?: string; condition?: string }[] | undefined) =>
  (rules ?? []).map((r) => [r.source, r.target, r.status ?? "200", r.condition].filter(Boolean).join(" ")).join("\n");

export function duration(start?: Date, end?: Date) {
  if (!start || !end) return undefined;
  const s = Math.round((end.getTime() - start.getTime()) / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}
