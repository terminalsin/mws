import { DescribeEventsCommand, type DBCluster, type DBInstance } from "@aws-sdk/client-rds";
import { ago, all, load, shortName, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, CopyValue, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import {
  ArrowUpCircle,
  Camera,
  Clock,
  Copy,
  Cpu,
  Database,
  GitBranch,
  Globe,
  HardDrive,
  Lock,
  MapPin,
  Play,
  Plus,
  RotateCcw,
  Shield,
  SlidersHorizontal,
  Square,
  Trash2,
  Shuffle,
  TriangleAlert,
} from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";

import { ICONS, STATUS_TONE, engineIcon, rds } from "../../../lib/clients";
import { clusters as listClusters, engineVersions, instances as listInstances, orderableClasses, snapshots, type Snap } from "../../../lib/data";
import { identifier, RETENTION } from "../../../lib/rules";
import { addInstance, changeCluster, changeInstance, createReplica, deleteDatabase, deleteMember, deleteSnapshot, modifyDatabase, snapshot, type Current } from "../actions";
import { CopySnapshot, RestorePointInTime, RestoreSnapshot } from "../forms.tsx";

export const metadata: Metadata = { title: "Database" };

const SNAPSHOT = identifier(255);
const ID = identifier(63);

type Props = { searchParams: Promise<{ id?: string; cluster?: string; tab?: string }> };

function connection(engine: string | undefined, host: string | undefined, port: number | undefined, user: string | undefined, db: string | undefined) {
  if (!host) return undefined;
  if (engine?.includes("postgres")) return `psql "host=${host} port=${port} user=${user} dbname=${db ?? "postgres"}"`;
  if (engine?.includes("mysql") || engine?.includes("mariadb")) return `mysql -h ${host} -P ${port} -u ${user} -p${db ? ` ${db}` : ""}`;
  return `${host}:${port}`;
}

/** PendingModifiedValues as readable "what → value" pairs. */
function pendingOf(p: Record<string, unknown> | undefined): [string, string][] {
  if (!p) return [];
  const label: Record<string, string> = {
    DBInstanceClass: "Class",
    AllocatedStorage: "Storage (GiB)",
    MasterUserPassword: "Master password",
    EngineVersion: "Engine version",
    BackupRetentionPeriod: "Backup retention",
    MultiAZ: "Multi-AZ",
    StorageType: "Storage type",
    Iops: "IOPS",
    StorageThroughput: "Throughput",
    DBInstanceIdentifier: "Identifier",
    DBClusterIdentifier: "Identifier",
    CACertificateIdentifier: "CA certificate",
    IAMDatabaseAuthenticationEnabled: "IAM authentication",
    DeletionProtection: "Deletion protection",
  };
  return Object.entries(p)
    .filter(([, v]) => v !== undefined && v !== null && typeof v !== "object")
    .map(([k, v]) => [label[k] ?? k, k === "MasterUserPassword" ? "changing" : String(v)]);
}

export default async function DbPage({ searchParams }: Props) {
  const { id, cluster, tab = "connectivity" } = await searchParams;
  const kind = cluster ? "cluster" : "instance";
  const name = cluster ?? id ?? "";
  const data = await load(async () => {
    if (cluster) {
      const c = (await listClusters({ DBClusterIdentifier: cluster }))[0];
      const [members, snaps] = await Promise.all([listInstances({ Filters: [{ Name: "db-cluster-id", Values: [cluster] }] }), snapshots({ cluster })]);
      return { c, i: undefined as DBInstance | undefined, members, snaps, parent: undefined as DBCluster | undefined };
    }
    const i = (await listInstances({ DBInstanceIdentifier: id }))[0];
    const [snaps, parent] = await Promise.all([
      i.DBClusterIdentifier ? Promise.resolve([] as Snap[]) : snapshots({ instance: id }),
      i.DBClusterIdentifier ? listClusters({ DBClusterIdentifier: i.DBClusterIdentifier }).then((r) => r[0]) : Promise.resolve(undefined),
    ]);
    return { c: undefined as DBCluster | undefined, i, members: [] as DBInstance[], snaps, parent };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.rds} back={{ href: "/rds", label: "Databases" }}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { c, i, members, snaps, parent } = data.value;
  const member = !!i?.DBClusterIdentifier;
  const back = member ? { href: `/rds/db?cluster=${encodeURIComponent(i!.DBClusterIdentifier!)}`, label: i!.DBClusterIdentifier! } : { href: "/rds", label: "Databases" };
  const engine = c?.Engine ?? i?.Engine ?? "";
  const aurora = engine.startsWith("aurora");
  const version = c?.EngineVersion ?? i?.EngineVersion;
  const status = c?.Status ?? i?.DBInstanceStatus;
  const host = c?.Endpoint ?? i?.Endpoint?.Address;
  const port = c?.Port ?? i?.Endpoint?.Port;
  const user = c?.MasterUsername ?? i?.MasterUsername ?? parent?.MasterUsername;
  const dbName = c?.DatabaseName ?? i?.DBName ?? parent?.DatabaseName;
  const running = status === "available";
  const stopped = status === "stopped";
  const retention = c?.BackupRetentionPeriod ?? i?.BackupRetentionPeriod ?? 0;
  const latest = c?.LatestRestorableTime ?? i?.LatestRestorableTime;
  const earliest = c?.EarliestRestorableTime;
  const replicaOf = i?.ReadReplicaSourceDBInstanceIdentifier;
  const replicas = i?.ReadReplicaDBInstanceIdentifiers ?? [];
  const pending = pendingOf((c?.PendingModifiedValues ?? i?.PendingModifiedValues) as Record<string, unknown> | undefined);
  const writer = (m: string) => (c ?? parent)?.DBClusterMembers?.find((x) => x.DBInstanceIdentifier === m)?.IsClusterWriter;
  const here = `/rds/db?${kind === "cluster" ? "cluster" : "id"}=${encodeURIComponent(name)}`;

  // What the forms offer: classes and upgrade targets for this engine,
  // names already in use.
  const [classes, versions, names] = await Promise.all([
    orderableClasses(engine).catch(() => [] as string[]),
    engineVersions(engine).catch(() => [] as { version: string; upgrades: string[] }[]),
    Promise.all([listInstances(), listClusters()]).then(
      ([a, b]) => [...a.map((x) => x.DBInstanceIdentifier!), ...b.map((x) => x.DBClusterIdentifier!)],
      () => [] as string[],
    ),
  ]);
  const upgrades = versions.find((v) => v.version === version)?.upgrades ?? [];
  const events =
    tab === "events"
      ? await load(async () => {
          const client = await rds();
          return all(
            (Marker) => client.send(new DescribeEventsCommand({ SourceIdentifier: name, SourceType: kind === "cluster" ? "db-cluster" : "db-instance", Duration: 20160, Marker })),
            (r) => r.Events,
            (r) => r.Marker,
          );
        })
      : null;

  const current: Current = {
    class: i?.DBInstanceClass,
    storage: aurora ? undefined : i?.AllocatedStorage,
    version,
    retention,
    deletionProtection: c?.DeletionProtection ?? i?.DeletionProtection,
    multiAz: i?.MultiAZ,
    public: i?.PubliclyAccessible,
  };
  const classList = (
    <datalist id="modify-classes">
      {classes.map((x) => (
        <option key={x} value={x} />
      ))}
    </datalist>
  );
  const modify = (
    <Sheet title={`Modify ${name}`} label="Modify" icon={<SlidersHorizontal size={16} />} testId="modify-database">
      <ActionForm action={modifyDatabase.bind(null, kind, name, current)} submit="Modify" testId="modify-database">
        {kind === "instance" && (
          <div className="form-row">
            <Field label="Instance class" rule={classes.length ? { enum: classes } : undefined}>
              <input name="class" defaultValue={i?.DBInstanceClass} list="modify-classes" spellCheck={false} autoComplete="off" />
            </Field>
            {!aurora && (
              <Field label="Storage (GiB)" rule={{ type: "integer", min: i?.AllocatedStorage ?? 20, max: 65536 }} hint="Storage can only grow">
                <input name="storage" type="number" defaultValue={i?.AllocatedStorage} />
              </Field>
            )}
          </div>
        )}
        {classList}
        {!member && (
          <>
            <div className="form-row">
              <Field label="Engine version">
                <select name="version" defaultValue={version}>
                  <option value={version}>{version} (current)</option>
                  {upgrades.map((v) => (
                    <option key={v} value={v}>
                      {v}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Backup retention (days)" rule={RETENTION}>
                <input name="retention" type="number" defaultValue={retention} />
              </Field>
            </div>
            <Field label="New master password" rule={{ minLength: 8, maxLength: engine.includes("postgres") ? 128 : 41, pattern: '^[!#-.0-?A-~]+$', hint: 'Printable ASCII except /, @, " and spaces', generate: "password" }}>
              <input name="password" type="password" autoComplete="new-password" placeholder="unchanged" />
            </Field>
            <div className="form-row">
              {kind === "instance" && !aurora && (
                <label className="check">
                  <input type="hidden" name="multiAzShown" value="1" />
                  <input type="checkbox" name="multiAz" defaultChecked={!!i?.MultiAZ} /> Multi-AZ
                </label>
              )}
              {kind === "instance" && (
                <label className="check">
                  <input type="checkbox" name="public" defaultChecked={!!i?.PubliclyAccessible} /> Publicly accessible
                </label>
              )}
              <label className="check">
                <input type="checkbox" name="deletionProtection" defaultChecked={!!current.deletionProtection} /> Deletion protection
              </label>
            </div>
          </>
        )}
        {member && (
          <>
            <input type="hidden" name="public" value={i?.PubliclyAccessible ? "on" : ""} />
            <input type="hidden" name="deletionProtection" value={current.deletionProtection ? "on" : ""} />
            <input type="hidden" name="retention" value={retention} />
          </>
        )}
        <label className="check">
          <input type="checkbox" name="now" defaultChecked /> Apply immediately
        </label>
      </ActionForm>
    </Sheet>
  );
  const finalName = `${name}-final-${new Date().toISOString().slice(0, 10)}`;
  const remove = member ? (
    <ActionForm action={deleteMember.bind(null, name)} submit="Delete instance" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-instance" />
  ) : (
    <Sheet title={`Delete ${name}`} label="Delete database" icon={<Trash2 size={16} />} testId="delete-database">
      <ActionForm action={deleteDatabase.bind(null, kind, name)} submit="Delete" tone="danger" confirm={`Delete ${name}?`} testId="delete-database">
        {kind === "cluster" && members.length > 0 && (
          <p className="muted">
            <TriangleAlert size={13} /> Deletes {members.map((m) => m.DBInstanceIdentifier).join(", ")} first.
          </p>
        )}
        {!replicaOf && (
          <>
            <label className="check">
              <input type="checkbox" name="final" /> Create final snapshot
            </label>
            <Field label="Final snapshot name" rule={{ ...SNAPSHOT, required: false }} taken={snaps.map((s) => s.id)} unique>
              <input name="finalName" defaultValue={finalName} spellCheck={false} />
            </Field>
          </>
        )}
        {kind === "instance" && retention > 0 && (
          <label className="check">
            <input type="checkbox" name="keepBackups" /> Retain automated backups
          </label>
        )}
      </ActionForm>
    </Sheet>
  );

  const tabs = [
    { label: "Connectivity & security", href: here, active: tab === "connectivity" },
    { label: "Configuration", href: `${here}&tab=configuration`, active: tab === "configuration" },
    ...(member ? [] : [{ label: "Maintenance & backups", href: `${here}&tab=backups`, active: tab === "backups", count: snaps.length || undefined }]),
    { label: "Logs & events", href: `${here}&tab=events`, active: tab === "events" },
    { label: "Tags", href: `${here}&tab=tags`, active: tab === "tags" },
  ];
  const subnetGroup = i?.DBSubnetGroup;
  const vpcId = subnetGroup?.VpcId;
  const sgs = c?.VpcSecurityGroups ?? i?.VpcSecurityGroups ?? [];
  const kms = c?.KmsKeyId ?? i?.KmsKeyId;
  const secret = c?.MasterUserSecret ?? i?.MasterUserSecret;
  const paramGroups = c
    ? [{ name: c.DBClusterParameterGroup, status: undefined as string | undefined, cluster: true }]
    : (i?.DBParameterGroups ?? []).map((p) => ({ name: p.DBParameterGroupName, status: p.ParameterApplyStatus, cluster: false }));
  const needsReboot = paramGroups.some((p) => p.status === "pending-reboot");

  return (
    <Page
      title={name}
      icon={engineIcon(engine)}
      back={back}
      subtitle={c?.DBClusterArn ?? i?.DBInstanceArn}
      actions={
        <>
          {modify}
          {!member && (
            <Sheet title="Take snapshot" label="Take snapshot" icon={<Camera size={16} />} testId="take-snapshot">
              <ActionForm action={snapshot.bind(null, kind, name)} submit="Take snapshot" testId="take-snapshot">
                <Field label="Snapshot name" rule={SNAPSHOT} generate={{ prefix: `${name}-` }} taken={snaps.map((s) => s.id)} unique>
                  <input name="name" required spellCheck={false} defaultValue={`${name}-${new Date().toISOString().slice(0, 10)}`} />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {!member && retention > 0 && latest && (
            <RestorePointInTime kind={kind} source={name} engine={engine} classes={classes} taken={names} earliest={earliest} latest={latest} />
          )}
          {kind === "instance" && !member && !aurora && !replicaOf && running && (
            <Sheet title="Create read replica" label="Create read replica" icon={<Copy size={16} />} testId="create-replica">
              <ActionForm action={createReplica.bind(null, name)} submit="Create read replica" testId="create-replica">
                <Field label="DB identifier" rule={ID} taken={names} unique>
                  <input name="id" required autoFocus spellCheck={false} defaultValue={`${name}-replica`.slice(0, 63)} />
                </Field>
                <Field label="Instance class" rule={classes.length ? { enum: classes } : undefined}>
                  <input name="class" defaultValue={i?.DBInstanceClass} list="modify-classes" spellCheck={false} autoComplete="off" />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {replicaOf && running && <ActionForm action={changeInstance.bind(null, name, "promote")} submit="Promote" icon={<ArrowUpCircle size={16} />} confirm={`Promote ${name} to a standalone database?`} />}
          {running && kind === "instance" && <ActionForm action={changeInstance.bind(null, name, "reboot")} submit="Reboot" icon={<RotateCcw size={16} />} />}
          {running && kind === "cluster" && <ActionForm action={changeCluster.bind(null, name, "reboot")} submit="Reboot" icon={<RotateCcw size={16} />} />}
          {running && kind === "cluster" && members.length > 1 && <ActionForm action={changeCluster.bind(null, name, "failover")} submit="Failover" icon={<Shuffle size={16} />} confirm={`Fail ${name} over to a reader?`} />}
          {running && !member && !replicaOf && (
            <ActionForm action={kind === "cluster" ? changeCluster.bind(null, name, "stop") : changeInstance.bind(null, name, "stop")} submit="Stop" icon={<Square size={16} />} />
          )}
          {stopped && <ActionForm action={kind === "cluster" ? changeCluster.bind(null, name, "start") : changeInstance.bind(null, name, "start")} submit="Start" icon={<Play size={16} />} />}
          {remove}
        </>
      }
    >
      <Specs
        items={[
          { label: "Engine", icon: <AwsIcon icon={engineIcon(engine)} size={16} />, value: `${engine} ${version}` },
          { label: "Status", icon: <Database size={15} />, value: <Status tone={STATUS_TONE(status)}>{status ?? ""}</Status> },
          member && { label: "Role", icon: <GitBranch size={15} />, value: <Pill tone={writer(name) ? "info" : "neutral"}>{writer(name) ? "Writer" : "Reader"}</Pill> },
          i?.DBInstanceClass && { label: "Class", icon: <Cpu size={15} />, value: i.DBInstanceClass },
          !aurora && i?.AllocatedStorage && { label: "Storage", icon: <HardDrive size={15} />, value: `${i.AllocatedStorage} GiB ${i.StorageType ?? ""}` },
          aurora && c && { label: "Storage", icon: <HardDrive size={15} />, value: c.StorageType ? `Aurora ${c.StorageType}` : "Aurora" },
          i?.AvailabilityZone && { label: "Availability Zone", icon: <MapPin size={15} />, value: i.AvailabilityZone },
          (c?.MultiAZ || i?.MultiAZ) && { label: "Multi-AZ", icon: <AwsIcon icon={ICONS.multiAz} size={16} />, value: "Multi-AZ" },
          (c?.StorageEncrypted || i?.StorageEncrypted) && { label: "Encrypted", icon: <Lock size={15} />, value: "Encrypted" },
          replicaOf && { label: "Replica of", icon: <Copy size={15} />, value: <Link href={`/rds/db?id=${encodeURIComponent(replicaOf)}`}>{replicaOf}</Link> },
          needsReboot && { label: "Parameters", icon: <TriangleAlert size={15} />, value: <Pill tone="warn">Reboot to apply parameters</Pill> },
        ]}
      />
      {pending.length > 0 && (
        <div className="banner" role="status" data-testid="pending-modifications">
          <Clock size={14} /> Pending: {pending.map(([k, v]) => `${k} → ${v}`).join(", ")}
        </div>
      )}
      {kind === "cluster" && (
        <Section
          title="Instances"
          count={members.length}
          plain
          actions={
            <Sheet title="Add instance" label="Add instance" icon={<Plus size={16} />} testId="add-instance">
              <ActionForm action={addInstance.bind(null, name, engine)} submit="Add instance" testId="add-instance">
                <Field label="DB identifier" rule={ID} taken={names} unique>
                  <input name="id" required autoFocus spellCheck={false} defaultValue={`${name}-instance-${members.length + 1}`.slice(0, 63)} />
                </Field>
                <Field label="Instance class" rule={classes.length ? { required: true, enum: classes } : { required: true }}>
                  <input name="class" defaultValue={members[0]?.DBInstanceClass ?? "db.t4g.medium"} list="modify-classes" spellCheck={false} autoComplete="off" />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Instances"
            empty={<Empty icon={engineIcon(engine)}>No instances: the cluster answers nothing until one is added</Empty>}
            rows={members.map((m) => ({
              key: m.DBInstanceIdentifier!,
              icon: <AwsIcon icon={engineIcon(m.Engine)} size={22} />,
              title: m.DBInstanceIdentifier,
              subtitle: m.AvailabilityZone,
              href: `/rds/db?id=${encodeURIComponent(m.DBInstanceIdentifier!)}`,
              meta: (
                <>
                  <Pill tone={writer(m.DBInstanceIdentifier!) ? "info" : "neutral"}>{writer(m.DBInstanceIdentifier!) ? "Writer" : "Reader"}</Pill>
                  <span>{m.DBInstanceClass}</span>
                  <Status tone={STATUS_TONE(m.DBInstanceStatus)}>{m.DBInstanceStatus ?? ""}</Status>
                </>
              ),
              actions:
                m.DBInstanceStatus !== "deleting" ? (
                  <ActionForm action={deleteMember.bind(null, m.DBInstanceIdentifier!)} submit={`Delete ${m.DBInstanceIdentifier}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${m.DBInstanceIdentifier}?`} />
                ) : undefined,
            }))}
          />
        </Section>
      )}
      <Segments label="Database" items={tabs} />
      {tab === "connectivity" && (
        <>
          {host && (
            <Section title="Connect">
              <CodeBlock value={connection(engine, host, port, user, dbName)} label="Connection command" />
              {c?.ReaderEndpoint && (
                <div className="muted">
                  Reader: <CopyValue value={c.ReaderEndpoint} label="Copy reader endpoint" />
                </div>
              )}
            </Section>
          )}
          <Section title="Networking">
            <Facts
              items={[
                host && ["Endpoint", <CopyValue key="e" value={host} label="Copy endpoint" />],
                port && ["Port", port],
                i?.AvailabilityZone && ["Availability Zone", i.AvailabilityZone],
                i?.SecondaryAvailabilityZone && ["Secondary zone", i.SecondaryAvailabilityZone],
                vpcId && ["VPC", <Link key="v" href={`/vpc/${vpcId}`}>{vpcId}</Link>],
                subnetGroup && [
                  "Subnet group",
                  <span key="s">
                    {subnetGroup.DBSubnetGroupName}
                    {subnetGroup.Subnets?.length ? <span className="muted"> · {subnetGroup.Subnets.map((s) => `${s.SubnetIdentifier} (${s.SubnetAvailabilityZone?.Name})`).join(", ")}</span> : null}
                  </span>,
                ],
                c?.DBSubnetGroup && ["Subnet group", c.DBSubnetGroup],
                kind === "instance" && ["Publicly accessible", i?.PubliclyAccessible ? <Pill key="p" tone="warn" icon={<Globe size={12} />}>Yes</Pill> : "No"],
              ]}
            />
          </Section>
          <Section title="Security">
            <Facts
              items={[
                sgs.length > 0 && [
                  "VPC security groups",
                  <span key="g" className="chips">
                    {sgs.map((g) => (
                      <Link key={g.VpcSecurityGroupId} href={`/ec2/group?id=${encodeURIComponent(g.VpcSecurityGroupId ?? "")}`}>
                        <Pill icon={<Shield size={12} />} tone={g.Status === "active" ? "neutral" : "warn"}>
                          {g.VpcSecurityGroupId}
                        </Pill>
                      </Link>
                    ))}
                  </span>,
                ],
                i?.CACertificateIdentifier && ["Certificate authority", i.CACertificateIdentifier],
                (c?.IAMDatabaseAuthenticationEnabled ?? i?.IAMDatabaseAuthenticationEnabled) && ["IAM authentication", "Enabled"],
                secret?.SecretArn && ["Master credentials", <Link key="m" href={`/secrets/secret?id=${encodeURIComponent(secret.SecretArn)}`}>Secrets Manager · {secret.SecretStatus}</Link>],
              ]}
            />
          </Section>
        </>
      )}
      {tab === "configuration" && (
        <Section>
          <Facts
            items={[
              ["Engine version", version],
              i?.DBInstanceClass && ["Instance class", i.DBInstanceClass],
              !aurora && i?.StorageType && ["Storage", `${i.AllocatedStorage} GiB ${i.StorageType}${i.Iops ? ` · ${i.Iops} IOPS` : ""}${i.MaxAllocatedStorage ? ` · autoscaling to ${i.MaxAllocatedStorage} GiB` : ""}`],
              dbName && ["Database name", dbName],
              user && ["Master username", user],
              ...paramGroups.map((p): [string, ReactNode] => [
                p.cluster ? "Cluster parameter group" : "Parameter group",
                <span key={p.name}>
                  {p.name} {p.status && p.status !== "in-sync" && <Pill tone="warn">{p.status}</Pill>}
                </span>,
              ]),
              i?.DBParameterGroups === undefined && parent?.DBClusterParameterGroup ? ["Cluster parameter group", parent.DBClusterParameterGroup] : null,
              ...(i?.OptionGroupMemberships ?? []).map((o): [string, ReactNode] => ["Option group", `${o.OptionGroupName}${o.Status && o.Status !== "in-sync" ? ` (${o.Status})` : ""}`]),
              kms && ["KMS key", <Link key="k" href={`/kms/key?id=${encodeURIComponent(kms)}`}>{shortName(kms)}</Link>],
              ["Deletion protection", (c?.DeletionProtection ?? i?.DeletionProtection) ? <Pill key="d" tone="info">Enabled</Pill> : "Disabled"],
              (c?.DbClusterResourceId ?? i?.DbiResourceId) && ["Resource ID", <code key="r">{c?.DbClusterResourceId ?? i?.DbiResourceId}</code>],
              (c?.ClusterCreateTime ?? i?.InstanceCreateTime) && ["Created", when(c?.ClusterCreateTime ?? i?.InstanceCreateTime)],
            ]}
          />
          {replicas.length > 0 && (
            <Section title="Read replicas" count={replicas.length} plain>
              <List
                label="Read replicas"
                rows={replicas.map((r) => ({ key: r, icon: <Copy size={18} />, title: r, href: `/rds/db?id=${encodeURIComponent(r)}` }))}
              />
            </Section>
          )}
        </Section>
      )}
      {tab === "backups" && !member && (
        <>
          <Section title="Backups">
            <Facts
              items={[
                ["Automated backups", retention > 0 ? `${retention} days` : <Pill key="b" tone="warn">Disabled</Pill>],
                (c?.PreferredBackupWindow ?? i?.PreferredBackupWindow) && ["Backup window", `${c?.PreferredBackupWindow ?? i?.PreferredBackupWindow} UTC`],
                earliest && ["Earliest restorable time", when(earliest)],
                latest && ["Latest restorable time", when(latest)],
                (c?.PreferredMaintenanceWindow ?? i?.PreferredMaintenanceWindow) && ["Maintenance window", `${c?.PreferredMaintenanceWindow ?? i?.PreferredMaintenanceWindow} UTC`],
                i && ["Auto minor version upgrade", i.AutoMinorVersionUpgrade ? "Enabled" : "Disabled"],
              ]}
            />
          </Section>
          <Section title="Snapshots" count={snaps.length} plain>
            <List
              label="Snapshots"
              empty={<Empty>No snapshots</Empty>}
              rows={snaps.map((s) => ({
                key: s.id,
                icon: <Camera size={18} />,
                title: s.id,
                meta: (
                  <>
                    <Pill>{s.type}</Pill>
                    <Status tone={STATUS_TONE(s.status)}>{s.status ?? ""}</Status>
                    <span>{ago(s.at)}</span>
                  </>
                ),
                actions: (
                  <>
                    {s.status === "available" && <RestoreSnapshot kind={s.kind} id={s.id} engine={engine} classes={classes} taken={names} />}
                    {s.status === "available" && <CopySnapshot kind={s.kind} id={s.id} taken={snaps.map((x) => x.id)} />}
                    {s.type === "manual" && <ActionForm action={deleteSnapshot.bind(null, s.kind, s.id)} submit={`Delete ${s.id}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.id}?`} />}
                  </>
                ),
              }))}
            />
          </Section>
        </>
      )}
      {tab === "events" &&
        events &&
        (events.ok ? (
          <List
            label="Events"
            empty={<Empty>No events in the last 14 days</Empty>}
            rows={events.value
              .slice()
              .sort((a, b) => (b.Date?.getTime() ?? 0) - (a.Date?.getTime() ?? 0))
              .map((e, n) => ({ key: `${e.Date?.toISOString()}-${n}`, title: <span className="row-subtitle">{e.Message}</span>, meta: <span title={when(e.Date)}>{ago(e.Date)}</span> }))}
          />
        ) : (
          <ErrorNotice error={events.error} />
        ))}
      {tab === "tags" && (((c?.TagList ?? i?.TagList) ?? []).length ? <Tags tags={c?.TagList ?? i?.TagList} /> : <Empty>No tags</Empty>)}
    </Page>
  );
}
