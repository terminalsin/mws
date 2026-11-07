import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { ECRClient } from "@aws-sdk/client-ecr";
import { ECSClient } from "@aws-sdk/client-ecs";
import { EFSClient } from "@aws-sdk/client-efs";
import { EKSClient } from "@aws-sdk/client-eks";
import { ElastiCacheClient } from "@aws-sdk/client-elasticache";
import { FirehoseClient } from "@aws-sdk/client-firehose";
import { IAMClient } from "@aws-sdk/client-iam";
import { KinesisClient } from "@aws-sdk/client-kinesis";
import { RDSClient } from "@aws-sdk/client-rds";
import { client } from "@mws-dashboard/aws";

export const ecr = () => client(ECRClient);
export const ecs = () => client(ECSClient);
export const eks = () => client(EKSClient);
export const rds = () => client(RDSClient);
export const elasticache = () => client(ElastiCacheClient);
export const efs = () => client(EFSClient);
export const kinesis = () => client(KinesisClient);
export const firehose = () => client(FirehoseClient);
export const ec2 = () => client(EC2Client);
export const iam = () => client(IAMClient);

export const ICONS = {
  ecr: "service/AmazonElasticContainerRegistry",
  repo: "resource/AmazonElasticContainerRegistryRegistry",
  image: "resource/AmazonElasticContainerRegistryImage",
  ecs: "service/AmazonElasticContainerService",
  ecsService: "resource/AmazonElasticContainerServiceService",
  task: "resource/AmazonElasticContainerServiceTask",
  container: "resource/AmazonElasticContainerServiceContainer1",
  eks: "service/AmazonElasticKubernetesService",
  rds: "service/AmazonRDS",
  aurora: "service/AmazonAurora",
  multiAz: "resource/AmazonRDSMultiAZ",
  multiAzCluster: "resource/AmazonRDSMultiAZDBCluster",
  elasticache: "service/AmazonElastiCache",
  cacheNode: "resource/AmazonElastiCacheCacheNode",
  efs: "service/AmazonEFS",
  fileSystem: "resource/AmazonElasticFileSystemFileSystem",
  kinesis: "service/AmazonKinesisDataStreams",
  firehose: "service/AmazonDataFirehose",
  vpc: "resource/AmazonVPCVirtualprivatecloudVPC",
};

/** Database and cache engine logos, then AWS's own engine icons. */
export function engineIcon(engine: string | undefined) {
  const e = (engine ?? "").toLowerCase();
  if (e.startsWith("aurora-postgresql")) return "resource/AmazonAuroraPostgreSQLInstance";
  if (e.startsWith("aurora")) return "resource/AmazonAuroraMySQLInstance";
  if (e.includes("postgres")) return "brand/postgresql";
  if (e.includes("mariadb")) return "brand/mariadb";
  if (e.includes("mysql")) return "brand/mysql";
  if (e.includes("valkey")) return "resource/AmazonElastiCacheElastiCacheforValkey";
  if (e.includes("redis")) return "brand/redis";
  if (e.includes("memcached")) return "resource/AmazonElastiCacheElastiCacheforMemcached";
  if (e.includes("oracle")) return "resource/AmazonAuroraOracleInstance";
  if (e.includes("sqlserver")) return "resource/AmazonAuroraSQLServerInstance";
  return ICONS.rds;
}

export const STATUS_TONE = (s: string | undefined): "good" | "warn" | "bad" | "neutral" => {
  const v = (s ?? "").toLowerCase();
  if (["available", "active", "running", "in-use", "ready"].includes(v)) return "good";
  if (["failed", "inaccessible-encryption-credentials", "incompatible-parameters", "storage-full", "deleting", "error", "degraded", "create_failed", "delete_failed"].includes(v)) return "bad";
  if (["stopped", "inactive", "disabled", "draining"].includes(v)) return "neutral";
  return "warn";
};

export const tagsOf = (list: { Key?: string; Value?: string; key?: string; value?: string }[] | undefined) =>
  Object.fromEntries((list ?? []).map((t) => [t.Key ?? t.key ?? "", t.Value ?? t.value ?? ""]).filter(([k]) => k));
