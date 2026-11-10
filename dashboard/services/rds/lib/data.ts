import "server-only";

import {
  DescribeDBClusterSnapshotsCommand,
  DescribeDBClustersCommand,
  DescribeDBEngineVersionsCommand,
  DescribeDBInstancesCommand,
  DescribeOrderableDBInstanceOptionsCommand,
  DescribeDBSnapshotsCommand,
  type DescribeDBClusterSnapshotsCommandInput,
  type DescribeDBClustersCommandInput,
  type DescribeDBInstancesCommandInput,
  type DescribeDBSnapshotsCommandInput,
} from "@aws-sdk/client-rds";
import { all } from "@mws-dashboard/aws";

import { rds } from "./clients";

// RDS pages its Describe* calls at 100 records: these follow Marker, so a
// list, count or lookup never stops at the first page.

export async function instances(input: DescribeDBInstancesCommandInput = {}) {
  const client = await rds();
  return all((Marker) => client.send(new DescribeDBInstancesCommand({ ...input, Marker })), (r) => r.DBInstances, (r) => r.Marker);
}

export async function clusters(input: DescribeDBClustersCommandInput = {}) {
  const client = await rds();
  return all((Marker) => client.send(new DescribeDBClustersCommand({ ...input, Marker })), (r) => r.DBClusters, (r) => r.Marker);
}

export async function instanceSnapshots(input: DescribeDBSnapshotsCommandInput = {}) {
  const client = await rds();
  return all((Marker) => client.send(new DescribeDBSnapshotsCommand({ ...input, Marker })), (r) => r.DBSnapshots, (r) => r.Marker);
}

export async function clusterSnapshots(input: DescribeDBClusterSnapshotsCommandInput = {}) {
  const client = await rds();
  return all((Marker) => client.send(new DescribeDBClusterSnapshotsCommand({ ...input, Marker })), (r) => r.DBClusterSnapshots, (r) => r.Marker);
}

/** A snapshot as the console lists it, instance or cluster alike. */
export interface Snap {
  kind: "instance" | "cluster";
  id: string;
  arn?: string;
  source?: string;
  engine?: string;
  version?: string;
  type?: string;
  status?: string;
  at?: Date;
  size?: number;
  encrypted?: boolean;
  progress?: number;
}

export async function snapshots(filter: { instance?: string; cluster?: string } = {}): Promise<Snap[]> {
  const [i, c] = await Promise.all([
    filter.cluster ? [] : instanceSnapshots(filter.instance ? { DBInstanceIdentifier: filter.instance } : {}),
    filter.instance ? [] : clusterSnapshots(filter.cluster ? { DBClusterIdentifier: filter.cluster } : {}),
  ]);
  return [
    ...i.map((s) => ({
      kind: "instance" as const,
      id: s.DBSnapshotIdentifier!,
      arn: s.DBSnapshotArn,
      source: s.DBInstanceIdentifier,
      engine: s.Engine,
      version: s.EngineVersion,
      type: s.SnapshotType,
      status: s.Status,
      at: s.SnapshotCreateTime,
      size: s.AllocatedStorage,
      encrypted: s.Encrypted,
      progress: s.PercentProgress,
    })),
    ...c.map((s) => ({
      kind: "cluster" as const,
      id: s.DBClusterSnapshotIdentifier!,
      arn: s.DBClusterSnapshotArn,
      source: s.DBClusterIdentifier,
      engine: s.Engine,
      version: s.EngineVersion,
      type: s.SnapshotType,
      status: s.Status,
      at: s.SnapshotCreateTime,
      // Aurora reports a nominal size; it is not storage anyone pays for.
      size: s.Engine?.startsWith("aurora") ? undefined : s.AllocatedStorage,
      encrypted: s.StorageEncrypted,
      progress: s.PercentProgress,
    })),
  ].sort((a, b) => (b.at?.getTime() ?? 0) - (a.at?.getTime() ?? 0));
}

/** The versions RDS offers an engine, newest first, each with the versions
 * it can be upgraded to. */
export async function engineVersions(engine: string) {
  const client = await rds();
  const list = await all(
    (Marker) => client.send(new DescribeDBEngineVersionsCommand({ Engine: engine, Marker })),
    (r) => r.DBEngineVersions,
    (r) => r.Marker,
  );
  return list
    .map((v) => ({ version: v.EngineVersion!, upgrades: (v.ValidUpgradeTarget ?? []).map((t) => t.EngineVersion!).filter(Boolean) }))
    .sort((a, b) => b.version.localeCompare(a.version, undefined, { numeric: true }));
}

/** The classes RDS offers an engine, from the orderable options. */
export async function orderableClasses(engine: string) {
  const client = await rds();
  const options = await all(
    (Marker) => client.send(new DescribeOrderableDBInstanceOptionsCommand({ Engine: engine, MaxRecords: 100, Marker })),
    (r) => r.OrderableDBInstanceOptions,
    (r) => r.Marker,
  );
  return [...new Set(options.map((o) => o.DBInstanceClass!).filter(Boolean))].sort();
}
