import {
  DescribeBackupPolicyCommand,
  DescribeFileSystemPolicyCommand,
  DescribeFileSystemsCommand,
  DescribeLifecycleConfigurationCommand,
  DescribeMountTargetSecurityGroupsCommand,
  DescribeReplicationConfigurationsCommand,
  type FileSystemDescription,
} from "@aws-sdk/client-efs";
import { ago, bytes, load, region, shortName } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags, type Rule } from "@mws-dashboard/ui";
import { CreateAccessPoint as Rules, CreateMountTarget, CreateReplicationConfiguration, UpdateFileSystem } from "@mws-dashboard/ui/model/efs";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { Archive, Gauge, HardDrive, KeyRound, Lock, MapPin, Pencil, Plus, Shield, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATUS_TONE, accessPoints, efs, fsHref, links, mountTargets } from "../../../lib/clients";
import { nameOf, securityGroupsOf, subnetsOf, vpcs } from "../../../lib/network";
import { ARCHIVE_OPTIONS, IA_OPTIONS, label } from "../../../lib/options";
import {
  createAccessPoint,
  createMountTarget,
  createReplication,
  deleteAccessPoint,
  deleteFileSystem,
  deleteMountTarget,
  deleteReplication,
  saveLifecycle,
  savePolicy,
  saveSecurityGroups,
  saveTags,
  setBackup,
  setProtection,
  updateFileSystem,
} from "../actions";

export const metadata: Metadata = { title: "File system" };

const NAME: Rule = { ...ruleAt(Rules, "Tags.Value"), required: false, hint: "Letters, digits, spaces and _ . : / = + - @" };
const PATH: Rule = { ...ruleAt(Rules, "RootDirectory.Path"), format: "dir", hint: "An absolute path, up to 4 levels" };
const UID: Rule = { ...ruleAt(Rules, "PosixUser.Uid"), default: 1000 };
const GID: Rule = { ...ruleAt(Rules, "PosixUser.Gid"), required: false, hint: "Defaults to the user id" };
const PERMISSIONS: Rule = { ...ruleAt(Rules, "RootDirectory.CreationInfo.Permissions"), required: false, hint: "Octal, like 755" };

const TABS = [
  ["general", "General"],
  ["network", "Network"],
  ["policy", "File system policy"],
  ["access-points", "Access points"],
  ["replication", "Replication"],
  ["tags", "Tags"],
] as const;

type Props = { searchParams: Promise<{ id?: string; tab?: string; warn?: string }> };

/** A configuration that may not exist (PolicyNotFound, ReplicationNotFound). */
async function optional<T>(read: () => Promise<T>): Promise<T | null> {
  try {
    return await read();
  } catch (e) {
    if (/NotFound$/.test((e as Error).name ?? "") && (e as Error).name !== "FileSystemNotFound") return null;
    throw e;
  }
}

// No "deny without TLS" statement: MWS is reached over plain HTTP, so it
// would lock the console out (PutFileSystemPolicy refuses it, as AWS would).
const policyTemplate = (arn: string) =>
  JSON.stringify(
    {
      Version: "2012-10-17",
      Statement: [
        { Sid: "ClientAccess", Effect: "Allow", Principal: { AWS: "*" }, Action: ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"], Resource: arn, Condition: { Bool: { "elasticfilesystem:AccessedViaMountTarget": "true" } } },
      ],
    },
    null,
    2,
  );

export default async function FileSystem({ searchParams }: Props) {
  const { id = "", tab = "general", warn } = await searchParams;
  const back = { href: "/efs", label: "File systems" };
  const client = await efs();
  const data = await load(async () => {
    const [f, targets] = await Promise.all([client.send(new DescribeFileSystemsCommand({ FileSystemId: id })).then((r) => r.FileSystems![0]), mountTargets(id)]);
    return { f, targets };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.fileSystem} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { f, targets } = data.value;
  const arn = f.FileSystemArn!;
  const dns = `${id}.efs.${await region()}.amazonaws.com`;
  const body = await (async () => {
    switch (tab) {
      case "network":
        return Network({ id, targets });
      case "policy":
        return Policy({ id, arn });
      case "access-points":
        return AccessPoints({ id });
      case "replication":
        return Replication({ id });
      case "tags":
        return (
          <Section
            title="Tags"
            actions={
              <Sheet title="Tags" label="Edit tags" icon={<Pencil size={15} aria-hidden />} testId="edit-fs-tags">
                <ActionForm action={saveTags.bind(null, id, (f.Tags ?? []).map((t) => t.Key!))} submit="Save" testId="edit-fs-tags">
                  <Field label="One Key=Value per line" format="tags" hint="Name is the file system's name">
                    <textarea name="tags" defaultValue={(f.Tags ?? []).map((t) => `${t.Key}=${t.Value}`).join("\n")} />
                  </Field>
                </ActionForm>
              </Sheet>
            }
          >
            {f.Tags?.length ? <Tags tags={f.Tags} /> : <span className="muted">None</span>}
          </Section>
        );
      default:
        return General({ id, f, dns });
    }
  })();
  return (
    <Page
      title={f.Name ?? id}
      icon={ICONS.fileSystem}
      back={back}
      subtitle={arn}
      actions={
        <ActionForm
          action={deleteFileSystem.bind(null, id)}
          submit="Delete file system"
          icon={<Trash2 size={16} />}
          tone="danger"
          confirm={`Delete ${f.Name ?? id}${targets.length ? ` and its ${targets.length} mount target${targets.length === 1 ? "" : "s"}` : ""}?`}
          testId="delete-file-system"
        />
      }
    >
      {warn && <ErrorNotice error={warn} />}
      <Specs
        items={[
          { label: "Size", icon: <HardDrive size={15} />, value: bytes(f.SizeInBytes?.Value) },
          { label: "State", icon: <AwsIcon icon={ICONS.efs} size={16} />, value: <Status tone={STATUS_TONE(f.LifeCycleState)}>{f.LifeCycleState ?? ""}</Status> },
          { label: "Throughput", icon: <Gauge size={15} />, value: f.ThroughputMode === "provisioned" ? `${f.ProvisionedThroughputInMibps} MiB/s` : f.ThroughputMode },
          f.Encrypted && { label: "Encrypted", icon: <Lock size={15} />, value: "Encrypted" },
          f.AvailabilityZoneName && { label: "One Zone", icon: <MapPin size={15} />, value: f.AvailabilityZoneName },
        ]}
      />
      <Segments items={TABS.map(([t, l]) => ({ label: l, href: fsHref(id, t === "general" ? undefined : t), active: t === tab, count: t === "network" ? targets.length : undefined }))} />
      {body}
    </Page>
  );
}

async function General({ id, f, dns }: { id: string; f: FileSystemDescription; dns: string }) {
  const client = await efs();
  const [lifecycle, backup] = await Promise.all([
    load(async () => (await client.send(new DescribeLifecycleConfigurationCommand({ FileSystemId: id }))).LifecyclePolicies ?? []),
    load(() => optional(async () => (await client.send(new DescribeBackupPolicyCommand({ FileSystemId: id }))).BackupPolicy)),
  ]);
  const policies = lifecycle.ok ? lifecycle.value : [];
  const ia = policies.find((p) => p.TransitionToIA)?.TransitionToIA;
  const archive = policies.find((p) => p.TransitionToArchive)?.TransitionToArchive;
  const primary = policies.some((p) => p.TransitionToPrimaryStorageClass);
  const backupOn = backup.ok && backup.value?.Status === "ENABLED";
  const protection = f.FileSystemProtection?.ReplicationOverwriteProtection;
  return (
    <>
      <Section
        title="General"
        actions={
          <Sheet title="Throughput" label="Edit throughput" icon={<Gauge size={15} aria-hidden />} testId="edit-throughput">
            <ActionForm action={updateFileSystem.bind(null, id)} submit="Save" testId="edit-throughput">
              <div className="form-row">
                <Field label="Throughput mode" rule={UpdateFileSystem.ThroughputMode}>
                  <select name="throughput" defaultValue={f.ThroughputMode}>
                    <option value="elastic">Elastic</option>
                    <option value="bursting">Bursting</option>
                    <option value="provisioned">Provisioned</option>
                  </select>
                </Field>
                <Field label="Provisioned MiB/s" rule={UpdateFileSystem.ProvisionedThroughputInMibps} hint="Provisioned only">
                  <input name="mibps" type="number" min={1} step="any" defaultValue={f.ProvisionedThroughputInMibps} />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
        }
      >
        <Facts
          items={[
            ["Performance mode", f.PerformanceMode === "maxIO" ? "Max I/O" : "General Purpose"],
            ["Throughput mode", f.ThroughputMode],
            f.ThroughputMode === "provisioned" && ["Provisioned throughput", `${f.ProvisionedThroughputInMibps} MiB/s`],
            ["Storage", f.AvailabilityZoneName ? `One Zone (${f.AvailabilityZoneName})` : "Regional"],
            f.KmsKeyId && ["KMS key", <Link href={links.key(f.KmsKeyId)}>{shortName(f.KmsKeyId)}</Link>],
            ["Mount targets", f.NumberOfMountTargets],
            ["Created", ago(f.CreationTime)],
            f.SizeInBytes?.ValueInIA ? ["Infrequent Access", bytes(f.SizeInBytes.ValueInIA)] : null,
            f.SizeInBytes?.ValueInArchive ? ["Archive", bytes(f.SizeInBytes.ValueInArchive)] : null,
          ]}
        />
      </Section>
      <Section
        title="Lifecycle management"
        actions={
          <Sheet title="Lifecycle management" label="Edit lifecycle management" icon={<Archive size={15} aria-hidden />} testId="edit-lifecycle">
            <ActionForm action={saveLifecycle.bind(null, id)} submit="Save" testId="edit-lifecycle">
              <Field label="Transition into Infrequent Access">
                <select name="ia" defaultValue={ia ?? ""}>
                  <option value="">None</option>
                  {IA_OPTIONS.map(([v, l]) => (
                    <option key={v} value={v}>
                      {l}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Transition into Archive">
                <select name="archive" defaultValue={archive ?? ""}>
                  <option value="">None</option>
                  {ARCHIVE_OPTIONS.map(([v, l]) => (
                    <option key={v} value={v}>
                      {l}
                    </option>
                  ))}
                </select>
              </Field>
              <label className="check">
                <input type="checkbox" name="primary" defaultChecked={primary} /> Back to Standard on first access
              </label>
            </ActionForm>
          </Sheet>
        }
      >
        {!lifecycle.ok ? (
          <ErrorNotice error={lifecycle.error} />
        ) : (
          <Facts items={[["To Infrequent Access", label(ia) ?? "None"], ["To Archive", label(archive) ?? "None"], ["To Standard", primary ? "On first access" : "None"]]} />
        )}
      </Section>
      <Section
        title="Data protection"
        actions={
          <>
            <ActionForm action={setBackup.bind(null, id, !backupOn)} submit={backupOn ? "Turn off automatic backups" : "Turn on automatic backups"} tone="plain" inline testId="toggle-backup" />
            <ActionForm action={setProtection.bind(null, id, protection !== "ENABLED")} submit={protection === "ENABLED" ? "Allow replication overwrite" : "Protect from replication overwrite"} tone="plain" inline />
          </>
        }
      >
        <Facts
          items={[
            ["Automatic backups", backup.ok ? <Status tone={backupOn ? "good" : "neutral"}>{backup.value?.Status ?? "DISABLED"}</Status> : backup.error],
            ["Replication overwrite protection", <Status tone={protection === "ENABLED" ? "good" : "neutral"}>{protection ?? "ENABLED"}</Status>],
          ]}
        />
      </Section>
      <Section title="Mount">
        <CodeBlock value={`sudo mount -t efs -o tls ${id}:/ /mnt/efs\n# or NFS\nsudo mount -t nfs4 -o nfsvers=4.1 ${dns}:/ /mnt/efs`} label="Mount commands" />
      </Section>
    </>
  );
}

async function Network({ id, targets }: { id: string; targets: Awaited<ReturnType<typeof mountTargets>> }) {
  const client = await efs();
  const vpc = targets[0]?.VpcId;
  const [groups, subnets, vpcGroups] = await Promise.all([
    load(async () =>
      Object.fromEntries(
        await Promise.all(targets.map(async (t) => [t.MountTargetId!, (await client.send(new DescribeMountTargetSecurityGroupsCommand({ MountTargetId: t.MountTargetId }))).SecurityGroups ?? []] as const)),
      ),
    ),
    vpc ? load(() => subnetsOf(vpc)) : null,
    vpc ? load(() => securityGroupsOf(vpc)) : null,
  ]);
  const networks = vpc ? null : await load(vpcs);
  const used = new Set(targets.map((t) => t.AvailabilityZoneName));
  const groupName = Object.fromEntries((vpcGroups?.ok ? vpcGroups.value : []).map((g) => [g.GroupId!, g.GroupName ?? g.GroupId!]));
  const free = (subnets?.ok ? subnets.value : []).filter((s) => !used.has(s.AvailabilityZone));
  const add =
    vpc ? (
      <Sheet title="Add mount target" label="Add mount target" icon={<Plus size={15} aria-hidden />} testId="create-mount-target">
        <ActionForm action={createMountTarget.bind(null, id)} submit="Create" testId="create-mount-target">
          <Field label="Subnet" rule={CreateMountTarget.SubnetId} member="SubnetId" hint="One mount target per Availability Zone">
            <select name="subnet" required>
              {free.map((s) => (
                <option key={s.SubnetId} value={s.SubnetId}>
                  {s.AvailabilityZone} · {nameOf(s.Tags) ?? s.SubnetId} ({s.CidrBlock})
                </option>
              ))}
            </select>
          </Field>
          <Field label="IP address" rule={CreateMountTarget.IpAddress} format="ipv4" hint="Automatic when empty">
            <input name="ip" />
          </Field>
          <SecurityGroupPicker groups={vpcGroups?.ok ? vpcGroups.value : []} selected={[]} />
        </ActionForm>
      </Sheet>
    ) : (
      <Sheet title="Add mount target" label="Add mount target" icon={<Plus size={15} aria-hidden />} testId="create-mount-target">
        <ActionForm action={createMountTarget.bind(null, id)} submit="Create" testId="create-mount-target">
          <Field label="Subnet ID" rule={CreateMountTarget.SubnetId} member="SubnetId" hint={networks?.ok ? `In one of ${networks.value.map((v) => nameOf(v.Tags) ?? v.VpcId).join(", ")}` : undefined}>
            <input name="subnet" required placeholder="subnet-…" />
          </Field>
          <Field label="IP address" rule={CreateMountTarget.IpAddress} format="ipv4" hint="Automatic when empty">
            <input name="ip" />
          </Field>
        </ActionForm>
      </Sheet>
    );
  return (
    <Section title="Mount targets" count={targets.length} actions={add} plain>
      {vpc && (
        <p className="muted">
          VPC <Link href={links.vpc(vpc)}>{vpc}</Link> · NFS needs TCP 2049 open from clients in each security group
        </p>
      )}
      {!groups.ok && <ErrorNotice error={groups.error} />}
      <List
        label="Mount targets"
        empty={<Empty icon={ICONS.efs} />}
        rows={targets.map((t) => {
          const sgs = groups.ok ? (groups.value[t.MountTargetId!] ?? []) : [];
          return {
            key: t.MountTargetId!,
            icon: <AwsIcon icon={ICONS.eni} size={22} />,
            title: (
              <>
                {t.IpAddress} <span className="muted">{t.AvailabilityZoneName}</span>
              </>
            ),
            subtitle: (
              <>
                <Link href={links.subnet(t.SubnetId!)}>{t.SubnetId}</Link>
                {t.NetworkInterfaceId && ` · ${t.NetworkInterfaceId}`}
                {sgs.map((g) => (
                  <span key={g}>
                    {" · "}
                    <Link href={links.group(g)}>{groupName[g] ?? g}</Link>
                  </span>
                ))}
              </>
            ),
            meta: <Status tone={STATUS_TONE(t.LifeCycleState)}>{t.LifeCycleState ?? ""}</Status>,
            actions: (
              <>
                <Sheet title={`Security groups of ${t.MountTargetId}`} label={`Edit security groups of ${t.AvailabilityZoneName}`} icon={<Shield size={15} aria-hidden />} testId={`edit-sgs-${t.AvailabilityZoneName}`}>
                  <ActionForm action={saveSecurityGroups.bind(null, t.MountTargetId!)} submit="Save" testId={`edit-sgs-${t.AvailabilityZoneName}`}>
                    <SecurityGroupPicker groups={vpcGroups?.ok ? vpcGroups.value : []} selected={sgs} />
                  </ActionForm>
                </Sheet>
                <ActionForm action={deleteMountTarget.bind(null, t.MountTargetId!)} submit={`Delete mount target ${t.AvailabilityZoneName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete the mount target in ${t.AvailabilityZoneName}? Clients mounted through it lose access.`} />
              </>
            ),
          };
        })}
      />
    </Section>
  );
}

function SecurityGroupPicker({ groups, selected }: { groups: { GroupId?: string; GroupName?: string; Description?: string }[]; selected: string[] }) {
  return (
    <fieldset className="field">
      <legend className="field-label">Security groups</legend>
      {groups.map((g) => (
        <label key={g.GroupId} className="check">
          <input type="checkbox" name="groups" value={g.GroupId} defaultChecked={selected.length ? selected.includes(g.GroupId!) : g.GroupName === "default"} /> {g.GroupName} <code className="muted">{g.GroupId}</code>
        </label>
      ))}
    </fieldset>
  );
}

async function Policy({ id, arn }: { id: string; arn: string }) {
  const policy = await load(async () => optional(async () => (await (await efs()).send(new DescribeFileSystemPolicyCommand({ FileSystemId: id }))).Policy));
  const doc = policy.ok ? policy.value : undefined;
  return (
    <Section
      title="File system policy"
      actions={
        <Sheet title="File system policy" label="Edit file system policy" icon={<Pencil size={15} aria-hidden />} testId="edit-fs-policy">
          <ActionForm action={savePolicy.bind(null, id)} submit="Save" testId="edit-fs-policy">
            <Field label="Policy JSON" format="policy" hint="Empty removes the policy">
              <textarea name="policy" rows={16} defaultValue={doc ? JSON.stringify(JSON.parse(doc), null, 2) : policyTemplate(arn)} />
            </Field>
            <label className="check">
              <input type="checkbox" name="bypass" /> Bypass the lockout safety check
            </label>
          </ActionForm>
        </Sheet>
      }
    >
      {!policy.ok ? <ErrorNotice error={policy.error} /> : doc ? <CodeBlock value={doc} label="File system policy" /> : <span className="muted">None: any client that can reach a mount target may mount and write</span>}
    </Section>
  );
}

async function AccessPoints({ id }: { id: string }) {
  const points = await load(() => accessPoints(id));
  return (
    <Section
      title="Access points"
      count={points.ok ? points.value.length : undefined}
      plain
      actions={
        <Sheet title="Create access point" label="Create access point" icon={<KeyRound size={16} />} testId="create-access-point">
          <ActionForm action={createAccessPoint.bind(null, id)} submit="Create" testId="create-access-point">
            <Field label="Name" rule={NAME} member="Tags.Value">
              <input name="name" autoFocus />
            </Field>
            <Field label="Root directory" rule={PATH} member="RootDirectory.Path">
              <input name="path" required defaultValue="/app" />
            </Field>
            <div className="form-row">
              <Field label="POSIX user id" rule={UID} member="PosixUser.Uid">
                <input name="uid" type="number" min={0} defaultValue={1000} />
              </Field>
              <Field label="POSIX group id" rule={GID} member="PosixUser.Gid">
                <input name="gid" type="number" min={0} />
              </Field>
              <Field label="Secondary group ids" hint="Comma-separated" member="PosixUser.SecondaryGids">
                <input name="secondary" />
              </Field>
            </div>
            <div className="form-row">
              <Field label="Owner user id" rule={{ ...UID, required: false, hint: "Defaults to the user id" }} member="RootDirectory.CreationInfo.OwnerUid">
                <input name="ownerUid" type="number" min={0} />
              </Field>
              <Field label="Owner group id" rule={GID} member="RootDirectory.CreationInfo.OwnerGid">
                <input name="ownerGid" type="number" min={0} />
              </Field>
              <Field label="Permissions" rule={PERMISSIONS} member="RootDirectory.CreationInfo.Permissions">
                <input name="permissions" defaultValue="755" />
              </Field>
            </div>
          </ActionForm>
        </Sheet>
      }
    >
      {!points.ok ? (
        <ErrorNotice error={points.error} />
      ) : (
        <List
          label="Access points"
          empty={<Empty icon={ICONS.efs} />}
          rows={points.value.map((p) => ({
            key: p.AccessPointId!,
            icon: <KeyRound size={18} />,
            title: p.Name ?? p.AccessPointId,
            subtitle: (
              <>
                {p.RootDirectory?.Path ?? "/"} · uid {p.PosixUser?.Uid ?? "—"} gid {p.PosixUser?.Gid ?? "—"}
                {p.PosixUser?.SecondaryGids?.length ? ` +${p.PosixUser.SecondaryGids.join(",")}` : ""}
                {p.RootDirectory?.CreationInfo && ` · owner ${p.RootDirectory.CreationInfo.OwnerUid}:${p.RootDirectory.CreationInfo.OwnerGid} ${p.RootDirectory.CreationInfo.Permissions}`}
                {" · "}
                <code className="clip">{p.AccessPointArn}</code>
              </>
            ),
            meta: <Status tone={STATUS_TONE(p.LifeCycleState)}>{p.LifeCycleState ?? ""}</Status>,
            actions: <ActionForm action={deleteAccessPoint.bind(null, p.AccessPointId!)} submit={`Delete ${p.AccessPointId}`} icon={<Trash2 size={15} />} tone="danger" confirm="Delete this access point?" />,
          }))}
        />
      )}
    </Section>
  );
}

async function Replication({ id }: { id: string }) {
  const repl = await load(() => optional(async () => (await (await efs()).send(new DescribeReplicationConfigurationsCommand({ FileSystemId: id }))).Replications ?? []));
  const list = repl.ok ? (repl.value ?? []) : [];
  const mine = list.find((r) => r.SourceFileSystemId === id);
  const asDestination = list.find((r) => r.SourceFileSystemId !== id);
  return (
    <Section
      title="Replication"
      plain
      actions={
        !mine && !asDestination ? (
          <Sheet title="Create replication" label="Create replication" icon={<Plus size={15} aria-hidden />} testId="create-replication">
            <ActionForm action={createReplication.bind(null, id)} submit="Create" testId="create-replication">
              <Field label="Destination Region" rule={ruleAt(CreateReplicationConfiguration, "Destinations.Region")} member="Destinations.Region">
                <input name="region" required defaultValue={await region()} />
              </Field>
              <Field label="Existing destination file system" rule={{ ...ruleAt(CreateReplicationConfiguration, "Destinations.FileSystemId"), required: false }} hint="Empty creates a new one" member="Destinations.FileSystemId">
                <input name="destination" placeholder="fs-…" />
              </Field>
              <div className="form-row">
                <Field label="One Zone (AZ)" rule={ruleAt(CreateReplicationConfiguration, "Destinations.AvailabilityZoneName")} member="Destinations.AvailabilityZoneName">
                  <input name="az" />
                </Field>
                <Field label="KMS key" rule={ruleAt(CreateReplicationConfiguration, "Destinations.KmsKeyId")} member="Destinations.KmsKeyId">
                  <input name="kms" />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
        ) : mine ? (
          <ActionForm action={deleteReplication.bind(null, id)} submit="Delete replication" icon={<Trash2 size={15} />} tone="danger" confirm="Delete this replication? The destination becomes writable." testId="delete-replication" />
        ) : undefined
      }
    >
      {!repl.ok ? (
        <ErrorNotice error={repl.error} />
      ) : asDestination ? (
        <p>
          Replica of <Link href={fsHref(asDestination.SourceFileSystemId!)}>{asDestination.SourceFileSystemId}</Link> ({asDestination.SourceFileSystemRegion}): read-only until the replication is deleted.
        </p>
      ) : mine ? (
        <List
          label="Destinations"
          rows={(mine.Destinations ?? []).map((d) => ({
            key: d.FileSystemId!,
            icon: <AwsIcon icon={ICONS.fileSystem} size={22} />,
            title: d.Region === mine.SourceFileSystemRegion ? <Link href={fsHref(d.FileSystemId!)}>{d.FileSystemId}</Link> : d.FileSystemId,
            subtitle: `${d.Region}${d.LastReplicatedTimestamp ? ` · last synced ${ago(d.LastReplicatedTimestamp)}` : ""}`,
            meta: (
              <>
                {d.StatusMessage && <Pill tone="bad">{d.StatusMessage}</Pill>}
                <Status tone={STATUS_TONE(d.Status === "ENABLED" ? "enabled" : d.Status)}>{d.Status ?? ""}</Status>
              </>
            ),
          }))}
        />
      ) : (
        <span className="muted">None</span>
      )}
    </Section>
  );
}
