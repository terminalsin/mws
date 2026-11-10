"use server";

import {
  CreateDBClusterCommand,
  CreateDBClusterSnapshotCommand,
  CreateDBInstanceCommand,
  CreateDBSnapshotCommand,
  DeleteDBClusterCommand,
  DeleteDBClusterSnapshotCommand,
  DeleteDBInstanceCommand,
  DeleteDBSnapshotCommand,
  RebootDBInstanceCommand,
  StartDBClusterCommand,
  StartDBInstanceCommand,
  StopDBClusterCommand,
  StopDBInstanceCommand,
} from "@aws-sdk/client-rds";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { rds } from "../../lib/clients";

/** Where RDS's complaints about a create land: by member, and by the
 * errors that name none. */
const CREATE_FIELDS = {
  DBInstanceIdentifier: "id",
  DBClusterIdentifier: "id",
  MasterUsername: "username",
  MasterUserPassword: "password",
  DBInstanceClass: "class",
  AllocatedStorage: "storage",
  StorageQuotaExceeded: "storage",
  InsufficientDBInstanceCapacity: "class",
};

export async function createDatabase(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const engine = required(form, "engine", "Engine");
    const id = required(form, "id", "DB identifier");
    const MasterUsername = required(form, "username", "Master username");
    const MasterUserPassword = required(form, "password", "Master password");
    const DBInstanceClass = text(form, "class") || "db.t4g.micro";
    const client = await rds();
    if (engine.startsWith("aurora")) {
      await client.send(new CreateDBClusterCommand({ DBClusterIdentifier: id, Engine: engine, MasterUsername, MasterUserPassword }));
      await client.send(new CreateDBInstanceCommand({ DBInstanceIdentifier: `${id}-instance-1`, DBClusterIdentifier: id, Engine: engine, DBInstanceClass }));
      redirect(`/rds/db?cluster=${encodeURIComponent(id)}`);
    }
    await client.send(
      new CreateDBInstanceCommand({
        DBInstanceIdentifier: id,
        Engine: engine,
        DBInstanceClass,
        MasterUsername,
        MasterUserPassword,
        AllocatedStorage: Number(text(form, "storage") || 20),
        MultiAZ: text(form, "multiAz") === "on",
        DBName: text(form, "dbName") || undefined,
      }),
    );
    redirect(`/rds/db?id=${encodeURIComponent(id)}`);
  }, { fields: CREATE_FIELDS });
}

export async function changeInstance(id: string, op: "start" | "stop" | "reboot") {
  return act(async () => {
    const client = await rds();
    if (op === "start") await client.send(new StartDBInstanceCommand({ DBInstanceIdentifier: id }));
    else if (op === "stop") await client.send(new StopDBInstanceCommand({ DBInstanceIdentifier: id }));
    else await client.send(new RebootDBInstanceCommand({ DBInstanceIdentifier: id }));
    return op === "start" ? "Starting" : op === "stop" ? "Stopping" : "Rebooting";
  }, "/rds", "/rds/db");
}

export async function changeCluster(id: string, op: "start" | "stop") {
  return act(async () => {
    const client = await rds();
    if (op === "start") await client.send(new StartDBClusterCommand({ DBClusterIdentifier: id }));
    else await client.send(new StopDBClusterCommand({ DBClusterIdentifier: id }));
    return op === "start" ? "Starting" : "Stopping";
  }, "/rds", "/rds/db");
}

export async function snapshot(kind: "instance" | "cluster", id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Snapshot name");
    const client = await rds();
    if (kind === "cluster") await client.send(new CreateDBClusterSnapshotCommand({ DBClusterIdentifier: id, DBClusterSnapshotIdentifier: name }));
    else await client.send(new CreateDBSnapshotCommand({ DBInstanceIdentifier: id, DBSnapshotIdentifier: name }));
    return `Snapshot ${name} started`;
  }, { revalidate: ["/rds", "/rds/db"], fields: { DBSnapshotIdentifier: "name", DBClusterSnapshotIdentifier: "name" } });
}

export async function deleteDatabase(kind: "instance" | "cluster", id: string) {
  return act(async () => {
    const client = await rds();
    if (kind === "cluster") await client.send(new DeleteDBClusterCommand({ DBClusterIdentifier: id, SkipFinalSnapshot: true }));
    else await client.send(new DeleteDBInstanceCommand({ DBInstanceIdentifier: id, SkipFinalSnapshot: true, DeleteAutomatedBackups: true }));
    redirect("/rds");
  });
}

export async function deleteSnapshot(kind: "instance" | "cluster", id: string) {
  return act(async () => {
    const client = await rds();
    if (kind === "cluster") await client.send(new DeleteDBClusterSnapshotCommand({ DBClusterSnapshotIdentifier: id }));
    else await client.send(new DeleteDBSnapshotCommand({ DBSnapshotIdentifier: id }));
    return "Snapshot deleted";
  }, "/rds");
}
