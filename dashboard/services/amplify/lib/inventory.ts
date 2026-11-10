import "server-only";

import { ListAppsCommand } from "@aws-sdk/client-amplify";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { amplify } from "./clients";

export async function apps(): Promise<InventoryItem[]> {
  const client = await amplify();
  const list = await all((nextToken) => client.send(new ListAppsCommand({ maxResults: 100, nextToken })), (r) => r.apps, (r) => r.nextToken);
  return list.map((a) => ({
    service: "amplify",
    type: "App",
    id: a.appArn!,
    name: a.name!,
    href: `/amplify/app?id=${a.appId}`,
    detail: a.defaultDomain,
    tags: a.tags,
    signal: a.productionBranch?.status === "FAILED" ? { tone: "bad" as const, text: "Deploy failed" } : undefined,
  }));
}
