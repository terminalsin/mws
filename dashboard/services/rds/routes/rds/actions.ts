"use server";

import {
  CopyDBClusterSnapshotCommand,
  CopyDBSnapshotCommand,
  CreateDBClusterCommand,
  CreateDBClusterSnapshotCommand,
  CreateDBInstanceCommand,
  CreateDBInstanceReadReplicaCommand,
  CreateDBSnapshotCommand,
  DeleteDBClusterCommand,
  DeleteDBClusterSnapshotCommand,
  DeleteDBInstanceCommand,
  DeleteDBSnapshotCommand,
  DescribeDBClustersCommand,
  FailoverDBClusterCommand,
  ModifyDBClusterCommand,
  ModifyDBInstanceCommand,
  PromoteReadReplicaCommand,
  RebootDBClusterCommand,
  RebootDBInstanceCommand,
  RestoreDBClusterFromSnapshotCommand,
  RestoreDBClusterToPointInTimeCommand,
  RestoreDBInstanceFromDBSnapshotCommand,
  RestoreDBInstanceToPointInTimeCommand,
  StartDBClusterCommand,
  StartDBInstanceCommand,
  StopDBClusterCommand,
  StopDBInstanceCommand,
} from "@aws-sdk/client-rds";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { rds } from "../../lib/clients";
import { instances } from "../../lib/data";

/** Where RDS's complaints about a create land: by member, and by the
 * errors that name none. */
const CREATE_FIELDS = {
  DBInstanceIdentifier: "id",
  DBClusterIdentifier: "id",
  TargetDBInstanceIdentifier: "id",
  MasterUsername: "username",
  MasterUserPassword: "password",
  DBInstanceClass: "class",
  AllocatedStorage: "storage",
  DBName: "dbName",
  DatabaseName: "dbName",
  BackupRetentionPeriod: "retention",
  EngineVersion: "version",
  RestoreTime: "time",
  StorageQuotaExceeded: "storage",
  InsufficientDBInstanceCapacity: "class",
  DBInstanceAlreadyExists: "id",
  DBInstanceAlreadyExistsFault: "id",
  DBClusterAlreadyExistsFault: "id",
  DBSnapshotAlreadyExists: "name",
  DBSnapshotAlreadyExistsFault: "name",
  DBClusterSnapshotAlreadyExistsFault: "name",
  PointInTimeRestoreNotEnabledFault: "time",
  InvalidRestoreFault: "time",
};

const dbHref = (kind: "instance" | "cluster", id: string) => `/rds/db?${kind === "cluster" ? "cluster" : "id"}=${encodeURIComponent(id)}`;
const on = (form: FormData, name: string) => text(form, name) === "on";
const int = (form: FormData, name: string) => (text(form, name) === "" ? undefined : Number(text(form, name)));

/** An Aurora cluster with no instance answers nothing: add its writer, and
 * if that fails, take the half-made cluster away again. */
async function addWriter(cluster: string, engine: string, DBInstanceClass: string) {
  const client = await rds();
  try {
    await client.send(new CreateDBInstanceCommand({ DBInstanceIdentifier: `${cluster}-instance-1`, DBClusterIdentifier: cluster, Engine: engine, DBInstanceClass }));
  } catch (e) {
    await client.send(new DeleteDBClusterCommand({ DBClusterIdentifier: cluster, SkipFinalSnapshot: true })).catch(() => {});
    throw e;
  }
}

export async function createDatabase(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const engine = required(form, "engine", "Engine");
    const id = required(form, "id", "DB identifier");
    const MasterUsername = required(form, "username", "Master username");
    const MasterUserPassword = required(form, "password", "Master password");
    const DBInstanceClass = text(form, "class") || "db.t4g.micro";
    const common = {
      EngineVersion: text(form, "version") || undefined,
      BackupRetentionPeriod: int(form, "retention"),
      DeletionProtection: on(form, "deletionProtection"),
      StorageEncrypted: on(form, "encrypted") || undefined,
    };
    const client = await rds();
    if (engine.startsWith("aurora")) {
      await client.send(
        new CreateDBClusterCommand({ DBClusterIdentifier: id, Engine: engine, MasterUsername, MasterUserPassword, DatabaseName: text(form, "dbName") || undefined, ...common }),
      );
      await addWriter(id, engine, DBInstanceClass);
      redirect(dbHref("cluster", id));
    }
    await client.send(
      new CreateDBInstanceCommand({
        DBInstanceIdentifier: id,
        Engine: engine,
        DBInstanceClass,
        MasterUsername,
        MasterUserPassword,
        AllocatedStorage: Number(text(form, "storage") || 20),
        MultiAZ: on(form, "multiAz"),
        PubliclyAccessible: on(form, "public") || undefined,
        DBName: text(form, "dbName") || undefined,
        ...common,
      }),
    );
    redirect(dbHref("instance", id));
  }, { fields: CREATE_FIELDS });
}

/** What the modify form started from, so only changed settings are sent
 * (RDS refuses some unchanged values, such as the same storage size). */
export interface Current {
  class?: string;
  storage?: number;
  version?: string;
  retention?: number;
  deletionProtection?: boolean;
  multiAz?: boolean;
  public?: boolean;
}

export async function modifyDatabase(kind: "instance" | "cluster", id: string, current: Current, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const changed = <T>(value: T | undefined, was: T | undefined) => (value === undefined || value === was ? undefined : value);
      const ApplyImmediately = on(form, "now");
      const MasterUserPassword = text(form, "password") || undefined;
      const EngineVersion = changed(text(form, "version") || undefined, current.version);
      const BackupRetentionPeriod = changed(int(form, "retention"), current.retention);
      const DeletionProtection = changed(on(form, "deletionProtection"), !!current.deletionProtection);
      const client = await rds();
      if (kind === "cluster") {
        const input = { EngineVersion, BackupRetentionPeriod, DeletionProtection, MasterUserPassword };
        if (Object.values(input).every((v) => v === undefined)) throw new Error("Nothing changed");
        await client.send(new ModifyDBClusterCommand({ DBClusterIdentifier: id, ApplyImmediately, AllowMajorVersionUpgrade: EngineVersion ? true : undefined, ...input }));
      } else {
        const input = {
          DBInstanceClass: changed(text(form, "class") || undefined, current.class),
          AllocatedStorage: changed(int(form, "storage"), current.storage),
          MultiAZ: form.has("multiAzShown") ? changed(on(form, "multiAz"), !!current.multiAz) : undefined,
          PubliclyAccessible: changed(on(form, "public"), !!current.public),
          EngineVersion,
          BackupRetentionPeriod,
          DeletionProtection,
          MasterUserPassword,
        };
        if (Object.values(input).every((v) => v === undefined)) throw new Error("Nothing changed");
        await client.send(new ModifyDBInstanceCommand({ DBInstanceIdentifier: id, ApplyImmediately, AllowMajorVersionUpgrade: EngineVersion ? true : undefined, ...input }));
      }
      return ApplyImmediately ? "Modifying" : "Changes pending for the next maintenance window";
    },
    { revalidate: ["/rds", "/rds/db"], fields: CREATE_FIELDS },
  );
}

export async function changeInstance(id: string, op: "start" | "stop" | "reboot" | "promote") {
  return act(async () => {
    const client = await rds();
    if (op === "start") await client.send(new StartDBInstanceCommand({ DBInstanceIdentifier: id }));
    else if (op === "stop") await client.send(new StopDBInstanceCommand({ DBInstanceIdentifier: id }));
    else if (op === "promote") await client.send(new PromoteReadReplicaCommand({ DBInstanceIdentifier: id }));
    else await client.send(new RebootDBInstanceCommand({ DBInstanceIdentifier: id }));
    return { start: "Starting", stop: "Stopping", reboot: "Rebooting", promote: "Promoting" }[op];
  }, "/rds", "/rds/db");
}

export async function changeCluster(id: string, op: "start" | "stop" | "reboot" | "failover") {
  return act(async () => {
    const client = await rds();
    if (op === "start") await client.send(new StartDBClusterCommand({ DBClusterIdentifier: id }));
    else if (op === "stop") await client.send(new StopDBClusterCommand({ DBClusterIdentifier: id }));
    else if (op === "reboot") await client.send(new RebootDBClusterCommand({ DBClusterIdentifier: id }));
    else await client.send(new FailoverDBClusterCommand({ DBClusterIdentifier: id }));
    return { start: "Starting", stop: "Stopping", reboot: "Rebooting", failover: "Failing over" }[op];
  }, "/rds", "/rds/db");
}

/** A reader (or, in an empty cluster, the writer) in an Aurora cluster. */
export async function addInstance(cluster: string, engine: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const id = required(form, "id", "DB identifier");
      await (await rds()).send(new CreateDBInstanceCommand({ DBInstanceIdentifier: id, DBClusterIdentifier: cluster, Engine: engine, DBInstanceClass: required(form, "class", "Instance class") }));
      return `Adding ${id}`;
    },
    { revalidate: ["/rds", "/rds/db"], fields: CREATE_FIELDS },
  );
}

export async function createReplica(source: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const id = required(form, "id", "DB identifier");
      await (await rds()).send(
        new CreateDBInstanceReadReplicaCommand({ DBInstanceIdentifier: id, SourceDBInstanceIdentifier: source, DBInstanceClass: text(form, "class") || undefined }),
      );
      redirect(dbHref("instance", id));
    },
    { fields: CREATE_FIELDS },
  );
}

export async function snapshot(kind: "instance" | "cluster", id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Snapshot name");
    const client = await rds();
    if (kind === "cluster") await client.send(new CreateDBClusterSnapshotCommand({ DBClusterIdentifier: id, DBClusterSnapshotIdentifier: name }));
    else await client.send(new CreateDBSnapshotCommand({ DBInstanceIdentifier: id, DBSnapshotIdentifier: name }));
    return `Snapshot ${name} started`;
  }, { revalidate: ["/rds", "/rds/db"], fields: { DBSnapshotIdentifier: "name", DBClusterSnapshotIdentifier: "name", ...CREATE_FIELDS } });
}

/** Wait until RDS has taken a cluster's instances away (they are removed
 * once their own deletion finishes). */
async function membersGone(cluster: string, timeoutMs = 120_000) {
  const client = await rds();
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const c = (await client.send(new DescribeDBClustersCommand({ DBClusterIdentifier: cluster }))).DBClusters?.[0];
    if (!c?.DBClusterMembers?.length) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

/** Delete a database the way RDS's console does: an Aurora cluster's
 * instances go first, then the cluster, with an optional final snapshot. */
export async function deleteDatabase(kind: "instance" | "cluster", id: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const finalName = on(form, "final") ? required(form, "finalName", "Final snapshot name") : undefined;
      const client = await rds();
      if (kind === "cluster") {
        const members = await instances({ Filters: [{ Name: "db-cluster-id", Values: [id] }] });
        for (const m of members) {
          if (m.DBInstanceStatus === "deleting") continue;
          await client.send(new DeleteDBInstanceCommand({ DBInstanceIdentifier: m.DBInstanceIdentifier!, SkipFinalSnapshot: true }));
        }
        if (members.length && !(await membersGone(id))) throw new Error(`The instances of ${id} are still being deleted; delete the cluster once they are gone`);
        await client.send(
          new DeleteDBClusterCommand({ DBClusterIdentifier: id, SkipFinalSnapshot: !finalName, FinalDBSnapshotIdentifier: finalName }),
        );
      } else {
        await client.send(
          new DeleteDBInstanceCommand({
            DBInstanceIdentifier: id,
            SkipFinalSnapshot: !finalName,
            FinalDBSnapshotIdentifier: finalName,
            DeleteAutomatedBackups: !on(form, "keepBackups"),
          }),
        );
      }
      redirect("/rds");
    },
    { fields: { FinalDBSnapshotIdentifier: "finalName", DBSnapshotAlreadyExists: "finalName", DBSnapshotAlreadyExistsFault: "finalName", DBClusterSnapshotAlreadyExistsFault: "finalName" } },
  );
}

/** One instance of a cluster (they never take a final snapshot of their own). */
export async function deleteMember(id: string) {
  return act(async () => {
    await (await rds()).send(new DeleteDBInstanceCommand({ DBInstanceIdentifier: id, SkipFinalSnapshot: true }));
    return `Deleting ${id}`;
  }, "/rds", "/rds/db");
}

export async function deleteSnapshot(kind: "instance" | "cluster", id: string) {
  return act(async () => {
    const client = await rds();
    if (kind === "cluster") await client.send(new DeleteDBClusterSnapshotCommand({ DBClusterSnapshotIdentifier: id }));
    else await client.send(new DeleteDBSnapshotCommand({ DBSnapshotIdentifier: id }));
    return "Snapshot deleted";
  }, "/rds", "/rds/db");
}

export async function copySnapshot(kind: "instance" | "cluster", id: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Snapshot name");
      const client = await rds();
      if (kind === "cluster") await client.send(new CopyDBClusterSnapshotCommand({ SourceDBClusterSnapshotIdentifier: id, TargetDBClusterSnapshotIdentifier: name, CopyTags: true }));
      else await client.send(new CopyDBSnapshotCommand({ SourceDBSnapshotIdentifier: id, TargetDBSnapshotIdentifier: name, CopyTags: true }));
      return `Copying to ${name}`;
    },
    { revalidate: ["/rds", "/rds/db"], fields: { TargetDBSnapshotIdentifier: "name", TargetDBClusterSnapshotIdentifier: "name", ...CREATE_FIELDS } },
  );
}

/** A new database from a snapshot. A cluster snapshot makes a cluster,
 * which gets its writer like a created one. */
export async function restoreSnapshot(kind: "instance" | "cluster", snapshotId: string, engine: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const id = required(form, "id", "DB identifier");
      const DBInstanceClass = text(form, "class") || undefined;
      const client = await rds();
      if (kind === "cluster") {
        await client.send(new RestoreDBClusterFromSnapshotCommand({ DBClusterIdentifier: id, SnapshotIdentifier: snapshotId, Engine: engine }));
        await addWriter(id, engine, DBInstanceClass ?? "db.t4g.medium");
        redirect(dbHref("cluster", id));
      }
      await client.send(new RestoreDBInstanceFromDBSnapshotCommand({ DBInstanceIdentifier: id, DBSnapshotIdentifier: snapshotId, DBInstanceClass }));
      redirect(dbHref("instance", id));
    },
    { fields: CREATE_FIELDS },
  );
}

/** A new database as the source was at a moment within its backup window. */
export async function restorePointInTime(kind: "instance" | "cluster", source: string, engine: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const id = required(form, "id", "DB identifier");
      const latest = text(form, "when") !== "custom";
      const raw = latest ? "" : required(form, "time", "Restore time");
      const RestoreTime = raw ? new Date(raw.endsWith("Z") ? raw : `${raw}Z`) : undefined;
      if (RestoreTime && Number.isNaN(RestoreTime.getTime())) throw new FieldError("time", "Not a date and time");
      const at = latest ? { UseLatestRestorableTime: true } : { RestoreTime };
      const client = await rds();
      if (kind === "cluster") {
        await client.send(new RestoreDBClusterToPointInTimeCommand({ DBClusterIdentifier: id, SourceDBClusterIdentifier: source, ...at }));
        await addWriter(id, engine, text(form, "class") || "db.t4g.medium");
        redirect(dbHref("cluster", id));
      }
      await client.send(
        new RestoreDBInstanceToPointInTimeCommand({ TargetDBInstanceIdentifier: id, SourceDBInstanceIdentifier: source, DBInstanceClass: text(form, "class") || undefined, ...at }),
      );
      redirect(dbHref("instance", id));
    },
    { fields: CREATE_FIELDS },
  );
}
