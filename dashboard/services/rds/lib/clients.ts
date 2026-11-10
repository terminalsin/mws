import "server-only";

import { RDSClient } from "@aws-sdk/client-rds";
import { client } from "@mws-dashboard/aws";

export const rds = () => client(RDSClient);

export const ICONS = {
  rds: "service/AmazonRDS",
  multiAz: "resource/AmazonRDSMultiAZ",
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
