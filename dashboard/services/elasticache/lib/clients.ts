import "server-only";

import { ElastiCacheClient } from "@aws-sdk/client-elasticache";
import { client } from "@mws-dashboard/aws";

export const elasticache = () => client(ElastiCacheClient);

export const ICONS = {
  rds: "service/AmazonRDS",
  elasticache: "service/AmazonElastiCache",
  cacheNode: "resource/AmazonElastiCacheCacheNode",
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
