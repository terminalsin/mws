import "server-only";

import { endpoint } from "@mws-dashboard/aws";

/** Where a branch's site answers in a browser: `<branch>.<appId>.amplifyapp.localhost` on MWS's port. */
export function siteUrl(appId: string, branch: string): string {
  const url = new URL(endpoint());
  const host = ["127.0.0.1", "localhost", "0.0.0.0"].includes(url.hostname) ? "localhost" : url.hostname;
  return `${url.protocol}//${branch.replace(/\//g, "-")}.${appId}.amplifyapp.${host}${url.port ? `:${url.port}` : ""}/`;
}

/** The same site through MWS's path form, which needs no DNS. */
export function sitePath(appId: string, branch: string): string {
  return `${endpoint()}/_aws/amplify/sites/${appId}/${branch.replace(/\//g, "-")}/`;
}
