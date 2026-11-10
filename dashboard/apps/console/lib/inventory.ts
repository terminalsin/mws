import "server-only";

import { describeError, type InventoryItem } from "@mws-dashboard/aws";
import { SERVICES } from "@mws-dashboard/ui";
import { cookies } from "next/headers";

import { INVENTORIES } from "./services.generated";

const cache = new Map<string, { at: number; items: InventoryItem[] }>();
const TTL = 5_000;

/** Every service's resources, for the caller's region. Each service package
 * lists its own (services/<id>/inventory.ts); a source that fails only
 * drops its own resources. */
export async function inventory(): Promise<InventoryItem[]> {
  const key = (await cookies()).get("mws-region")?.value ?? "";
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL) return hit.items;
  const sources = Object.values(INVENTORIES).flat();
  const settled = await Promise.allSettled(sources.map((source) => source()));
  const items = settled.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
  for (const r of settled) if (r.status === "rejected") console.warn(`inventory: ${describeError(r.reason)}`);
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
  Stack: "resource/AWSCloudFormationStack",
  Account: "resource/AWSOrganizationsAccount",
  "Resource share": "service/AWSResourceAccessManager",
  Guardrail: "resource/AWSIdentityAccessManagementPermissions",
  App: "service/AWSAmplify",
  "Package repository": "service/AWSCodeArtifact",
  "Image pipeline": "service/AmazonEC2ImageBuilder",
  "Auto Scaling group": "resource/AmazonEC2AutoScaling",
  Product: "service/AWSMarketplace",
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
