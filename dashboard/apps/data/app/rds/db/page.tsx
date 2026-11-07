import { DescribeDBClustersCommand, DescribeDBInstancesCommand, DescribeDBSnapshotsCommand, DescribeDBClusterSnapshotsCommand, type DBInstance } from "@aws-sdk/client-rds";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { Camera, Clock, Cpu, Database, HardDrive, Lock, Network, Play, RotateCcw, Square, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, engineIcon, rds } from "../../../lib/clients";
import { changeCluster, changeInstance, deleteDatabase, snapshot } from "../actions";

export const metadata: Metadata = { title: "Database" };

type Props = { searchParams: Promise<{ id?: string; cluster?: string }> };

function connection(engine: string | undefined, host: string | undefined, port: number | undefined, user: string | undefined, db: string | undefined) {
  if (!host) return undefined;
  if (engine?.includes("postgres")) return `psql "host=${host} port=${port} user=${user} dbname=${db ?? "postgres"}"`;
  if (engine?.includes("mysql") || engine?.includes("mariadb")) return `mysql -h ${host} -P ${port} -u ${user} -p${db ? ` ${db}` : ""}`;
  return `${host}:${port}`;
}

export default async function DbPage({ searchParams }: Props) {
  const { id, cluster } = await searchParams;
  const back = { href: "/rds", label: "Databases" };
  const kind = cluster ? "cluster" : "instance";
  const name = cluster ?? id ?? "";
  const data = await load(async () => {
    const client = await rds();
    if (cluster) {
      const c = (await client.send(new DescribeDBClustersCommand({ DBClusterIdentifier: cluster }))).DBClusters![0];
      const [members, snaps] = await Promise.all([
        client.send(new DescribeDBInstancesCommand({ Filters: [{ Name: "db-cluster-id", Values: [cluster] }] })).then((r) => r.DBInstances ?? []),
        client.send(new DescribeDBClusterSnapshotsCommand({ DBClusterIdentifier: cluster })).then((r) => r.DBClusterSnapshots ?? []),
      ]);
      return { c, i: undefined as DBInstance | undefined, members, snaps: snaps.map((s) => ({ id: s.DBClusterSnapshotIdentifier!, type: s.SnapshotType, status: s.Status, at: s.SnapshotCreateTime })) };
    }
    const i = (await client.send(new DescribeDBInstancesCommand({ DBInstanceIdentifier: id }))).DBInstances![0];
    const snaps = (await client.send(new DescribeDBSnapshotsCommand({ DBInstanceIdentifier: id }))).DBSnapshots ?? [];
    return { c: undefined, i, members: [] as DBInstance[], snaps: snaps.map((s) => ({ id: s.DBSnapshotIdentifier!, type: s.SnapshotType, status: s.Status, at: s.SnapshotCreateTime })) };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.rds} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { c, i, members, snaps } = data.value;
  const engine = c?.Engine ?? i?.Engine;
  const status = c?.Status ?? i?.DBInstanceStatus;
  const host = c?.Endpoint ?? i?.Endpoint?.Address;
  const port = c?.Port ?? i?.Endpoint?.Port;
  const user = c?.MasterUsername ?? i?.MasterUsername;
  const dbName = c?.DatabaseName ?? i?.DBName;
  const running = status === "available";
  const stopped = status === "stopped";
  return (
    <Page
      title={name}
      icon={engineIcon(engine)}
      back={back}
      subtitle={c?.DBClusterArn ?? i?.DBInstanceArn}
      actions={
        <>
          <Sheet title="Take snapshot" label="Take snapshot" icon={<Camera size={16} />} testId="take-snapshot">
            <ActionForm action={snapshot.bind(null, kind, name)} submit="Take snapshot" testId="take-snapshot">
              <Field label="Snapshot name">
                <input name="name" required defaultValue={`${name}-${new Date().toISOString().slice(0, 10)}`} />
              </Field>
            </ActionForm>
          </Sheet>
          {running && kind === "instance" && <ActionForm action={changeInstance.bind(null, name, "reboot")} submit="Reboot" icon={<RotateCcw size={16} />} />}
          {running && <ActionForm action={kind === "cluster" ? changeCluster.bind(null, name, "stop") : changeInstance.bind(null, name, "stop")} submit="Stop" icon={<Square size={16} />} />}
          {stopped && <ActionForm action={kind === "cluster" ? changeCluster.bind(null, name, "start") : changeInstance.bind(null, name, "start")} submit="Start" icon={<Play size={16} />} />}
          <ActionForm action={deleteDatabase.bind(null, kind, name)} submit="Delete database" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name} without a final snapshot?`} testId="delete-database" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Engine", icon: <AwsIcon icon={engineIcon(engine)} size={16} />, value: `${engine} ${c?.EngineVersion ?? i?.EngineVersion}` },
          { label: "Status", icon: <Database size={15} />, value: <Status tone={STATUS_TONE(status)}>{status}</Status> },
          i?.DBInstanceClass && { label: "Class", icon: <Cpu size={15} />, value: i.DBInstanceClass },
          (i?.AllocatedStorage || c?.AllocatedStorage) && { label: "Storage", icon: <HardDrive size={15} />, value: `${i?.AllocatedStorage ?? c?.AllocatedStorage} GiB ${i?.StorageType ?? c?.StorageType ?? ""}` },
          (c?.MultiAZ || i?.MultiAZ) && { label: "Multi-AZ", icon: <AwsIcon icon={ICONS.multiAz} size={16} />, value: "Multi-AZ" },
          (c?.StorageEncrypted || i?.StorageEncrypted) && { label: "Encrypted", icon: <Lock size={15} />, value: "Encrypted" },
          (i?.DBSubnetGroup?.VpcId ?? undefined) && { label: "VPC", icon: <AwsIcon icon={ICONS.vpc} size={16} />, value: <a href={`/networking/vpc/${i!.DBSubnetGroup!.VpcId}`}>{i!.DBSubnetGroup!.VpcId}</a> },
          (c?.BackupRetentionPeriod ?? i?.BackupRetentionPeriod) ? { label: "Backups", icon: <Clock size={15} />, value: `${c?.BackupRetentionPeriod ?? i?.BackupRetentionPeriod}d` } : null,
        ]}
      />
      {host && (
        <Section title="Connect">
          <CodeBlock value={connection(engine, host, port, user, dbName)} label="Connection command" />
          {c?.ReaderEndpoint && (
            <div className="muted">
              <Network size={13} /> Reader: <code>{c.ReaderEndpoint}</code>
            </div>
          )}
        </Section>
      )}
      {members.length > 0 && (
        <Section title="Instances" count={members.length} plain>
          <List
            label="Instances"
            rows={members.map((m) => {
              const writer = c?.DBClusterMembers?.find((x) => x.DBInstanceIdentifier === m.DBInstanceIdentifier)?.IsClusterWriter;
              return {
                key: m.DBInstanceIdentifier!,
                icon: <AwsIcon icon={engineIcon(m.Engine)} size={22} />,
                title: m.DBInstanceIdentifier,
                subtitle: m.AvailabilityZone,
                meta: (
                  <>
                    <Pill tone={writer ? "info" : "neutral"}>{writer ? "Writer" : "Reader"}</Pill>
                    <span>{m.DBInstanceClass}</span>
                    <Status tone={STATUS_TONE(m.DBInstanceStatus)}>{m.DBInstanceStatus}</Status>
                  </>
                ),
              };
            })}
          />
        </Section>
      )}
      {snaps.length > 0 && (
        <Section title="Snapshots" count={snaps.length} plain>
          <List
            label="Snapshots"
            rows={snaps.map((s) => ({
              key: s.id,
              icon: <Camera size={18} />,
              title: s.id,
              meta: (
                <>
                  <Pill>{s.type}</Pill>
                  <Status tone={STATUS_TONE(s.status)}>{s.status}</Status>
                  <span>{ago(s.at)}</span>
                </>
              ),
            }))}
          />
        </Section>
      )}
      <Tags tags={c?.TagList ?? i?.TagList} />
    </Page>
  );
}
