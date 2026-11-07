import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";
import { SERVICES, ZONES } from "@mws-dashboard/ui";
import { headers } from "next/headers";

// Where the shell reaches each zone's server (as its rewrites do).
function zoneUrl(id: string, port: number) {
  return (process.env[`MWS_DASHBOARD_${id.toUpperCase()}_URL`] ?? `http://127.0.0.1:${port}`).replace(/\/$/, "");
}

const cache = new Map<string, { at: number; items: InventoryItem[] }>();
const TTL = 5_000;

/** Every zone's resources, for the caller's region. Each zone answers for
 * its own services at `<basePath>/api/inventory`; a zone that is down only
 * drops its own resources. */
export async function inventory(): Promise<InventoryItem[]> {
  const cookie = (await headers()).get("cookie") ?? "";
  const key = /mws-region=([^;]+)/.exec(cookie)?.[1] ?? "";
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL) return hit.items;
  const lists = await Promise.all(
    ZONES.filter((z) => z.id !== "shell").map(async (z) => {
      try {
        const response = await fetch(`${zoneUrl(z.id, z.port)}${z.basePath}/api/inventory`, {
          headers: { cookie },
          cache: "no-store",
          signal: AbortSignal.timeout(15_000),
        });
        if (!response.ok) return [];
        return ((await response.json()) as { items: InventoryItem[] }).items;
      } catch {
        return [];
      }
    }),
  );
  const items = lists.flat();
  cache.set(key, { at: Date.now(), items });
  return items;
}

const TYPE_ICONS: Record<string, string> = {
  Alarm: "resource/AmazonCloudWatchAlarm",
  Bucket: "resource/AmazonSimpleStorageServiceBucket",
  "Event bus": "resource/AmazonEventBridgeCustomEventBus",
  Function: "resource/AWSLambdaLambdaFunction",
  Instance: "resource/AmazonEC2Instance",
  Key: "resource/AWSIdentityAccessManagementDataEncryptionKey",
  "Log group": "resource/AmazonCloudWatchLogs",
  Parameter: "resource/AWSSystemsManagerParameterStore",
  Role: "resource/AWSIdentityAccessManagementRole",
  Rule: "resource/AmazonEventBridgeRule",
  User: "resource/User",
  Topic: "resource/AmazonSimpleNotificationServiceTopic",
  Queue: "resource/AmazonSimpleQueueServiceQueue",
  "Dead-letter queue": "resource/AmazonSimpleQueueServiceQueue",
  "Email identity": "resource/AmazonSimpleEmailServiceEmail",
  "Domain identity": "resource/AmazonSimpleEmailServiceEmail",
  VPC: "resource/AmazonVPCVirtualprivatecloudVPC",
  "Hosted zone": "resource/AmazonRoute53HostedZone",
  "Load balancer": "resource/ElasticLoadBalancingApplicationLoadBalancer",
  Accelerator: "service/AWSGlobalAccelerator",
  Certificate: "service/AWSCertificateManager",
  "Certificate authority": "resource/AWSCertificateManagerCertificateAuthority",
  "DB cluster": "service/AmazonAurora",
  "DB instance": "service/AmazonRDS",
  Cache: "resource/AmazonElastiCacheCacheNode",
  "Serverless cache": "service/AmazonElastiCache",
  Repository: "resource/AmazonElasticContainerRegistryRegistry",
  "ECS cluster": "service/AmazonElasticContainerService",
  "EKS cluster": "service/AmazonElasticKubernetesService",
  "File system": "resource/AmazonElasticFileSystemFileSystem",
  "Data stream": "service/AmazonKinesisDataStreams",
  "Firehose stream": "service/AmazonDataFirehose",
};

/** The icon of a resource's type, or else its service's. */
export function iconOf(item: InventoryItem) {
  return TYPE_ICONS[item.type] ?? serviceOf(item)?.icon ?? "category/ManagementTools";
}

export function serviceOf(item: InventoryItem) {
  return SERVICES.find((s) => s.id === item.service);
}

/** The text search and grouping see for a resource. */
export function searchText(item: InventoryItem) {
  const s = serviceOf(item);
  return [item.name, item.type, s?.short, s?.name, item.detail, ...Object.entries(item.tags ?? {}).flat()].filter(Boolean).join(" ");
}
