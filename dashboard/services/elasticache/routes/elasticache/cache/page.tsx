import { DescribeCacheSubnetGroupsCommand, ListAllowedNodeTypeModificationsCommand, ListTagsForResourceCommand, type CacheCluster, type ReplicationGroup, type ServerlessCache } from "@aws-sdk/client-elasticache";
import { ago, load, shortName, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { Camera, Clock, Cpu, Database, Gauge, Layers, Lock, RotateCcw, Shield, Shuffle, SlidersHorizontal, Trash2, TriangleAlert } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, STATUS_TONE, elasticache, engineIcon } from "../../../lib/clients";
import { cacheClusters, engineVersions, nodeTypes, replicationGroups, serverlessCaches, snapshots } from "../../../lib/elasticache";
import { SNAPSHOT } from "../../../lib/rules";
import { deleteCache, deleteSnapshot, modifyCache, rebootNodes, resizeGroup, takeSnapshot, testFailover, type Current } from "../actions";
import { CopySnapshot, RestoreSnapshot } from "../forms.tsx";

export const metadata: Metadata = { title: "Cache" };

type Props = { searchParams: Promise<{ id?: string; serverless?: string; cluster?: string; tab?: string }> };

interface Node {
  id: string;
  cluster: string;
  nodeId: string;
  role?: string;
  status?: string;
  az?: string;
  endpoint?: string;
}

const cliFor = (engine: string) => (engine === "valkey" ? "valkey-cli" : "redis-cli");

export default async function CachePage({ searchParams }: Props) {
  const { id, serverless, cluster, tab = "nodes" } = await searchParams;
  const kind = serverless ? "serverless" : id ? "group" : "cluster";
  const name = serverless ?? id ?? cluster ?? "";
  const back = { href: "/elasticache", label: "Caches" };
  const data = await load(async () => {
    let s: ServerlessCache | undefined;
    let g: ReplicationGroup | undefined;
    let c: CacheCluster | undefined;
    let members: CacheCluster[] = [];
    if (serverless) s = (await serverlessCaches(serverless))[0];
    else if (id) {
      g = (await replicationGroups(id))[0];
      const ids = new Set(g.MemberClusters ?? []);
      members = (await cacheClusters()).filter((m) => ids.has(m.CacheClusterId!));
    } else c = (await cacheClusters({ CacheClusterId: cluster }))[0];
    const first = c ?? members[0];
    const client = await elasticache();
    const arn = s?.ARN ?? g?.ARN ?? c?.ARN;
    const [subnetGroup, tags, snaps, allowed] = await Promise.all([
      first?.CacheSubnetGroupName
        ? client.send(new DescribeCacheSubnetGroupsCommand({ CacheSubnetGroupName: first.CacheSubnetGroupName })).then((r) => r.CacheSubnetGroups?.[0], () => undefined)
        : undefined,
      arn ? client.send(new ListTagsForResourceCommand({ ResourceName: arn })).then((r) => r.TagList ?? [], () => []) : [],
      kind === "cluster" && first?.Engine === "memcached" ? [] : snapshots(serverless ? { serverless } : id ? { group: id } : { cluster }).catch(() => []),
      kind === "serverless"
        ? []
        : client.send(new ListAllowedNodeTypeModificationsCommand(id ? { ReplicationGroupId: id } : { CacheClusterId: cluster })).then(
            (r) => [...(r.ScaleUpModifications ?? []), ...(r.ScaleDownModifications ?? [])],
            () => [] as string[],
          ),
    ]);
    return { s, g, c, members, subnetGroup, tags, snaps, allowed };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.elasticache} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { s, g, c, members, subnetGroup, tags, snaps, allowed } = data.value;
  const first = c ?? members[0];
  const engine = s?.Engine ?? g?.Engine ?? c?.Engine ?? "redis";
  const memcached = engine === "memcached";
  const version = s?.FullEngineVersion ?? s?.MajorEngineVersion ?? first?.EngineVersion;
  const status = s?.Status ?? g?.Status ?? c?.CacheClusterStatus;
  const tls = !!(s || g?.TransitEncryptionEnabled || c?.TransitEncryptionEnabled);
  const clusterMode = !!g?.ClusterEnabled;
  const endpoint = s?.Endpoint ?? g?.ConfigurationEndpoint ?? g?.NodeGroups?.[0]?.PrimaryEndpoint ?? c?.ConfigurationEndpoint ?? c?.CacheNodes?.[0]?.Endpoint;
  const host = endpoint?.Address;
  const port = endpoint?.Port;
  const cli = memcached
    ? tls
      ? `openssl s_client -connect ${host}:${port} -crlf`
      : `telnet ${host} ${port}`
    : `${cliFor(engine)} -h ${host} -p ${port}${tls ? " --tls" : ""}${s || clusterMode ? " -c" : ""}`;
  const retention = s?.SnapshotRetentionLimit ?? g?.SnapshotRetentionLimit ?? c?.SnapshotRetentionLimit ?? 0;
  const memberOf = new Map(members.map((m) => [m.CacheClusterId!, m]));
  const shards = (g?.NodeGroups ?? []).map((ng) => ({
    id: ng.NodeGroupId!,
    status: ng.Status,
    slots: ng.Slots,
    reader: ng.ReaderEndpoint,
    nodes: (ng.NodeGroupMembers ?? []).map(
      (m): Node => ({
        id: m.CacheClusterId!,
        cluster: m.CacheClusterId!,
        nodeId: m.CacheNodeId ?? "0001",
        role: m.CurrentRole ?? (clusterMode ? undefined : "replica"),
        status: memberOf.get(m.CacheClusterId!)?.CacheClusterStatus,
        az: m.PreferredAvailabilityZone,
        endpoint: m.ReadEndpoint?.Address ? `${m.ReadEndpoint.Address}:${m.ReadEndpoint.Port}` : undefined,
      }),
    ),
  }));
  const cNodes: Node[] = (c?.CacheNodes ?? []).map((n) => ({
    id: n.CacheNodeId!,
    cluster: c!.CacheClusterId!,
    nodeId: n.CacheNodeId!,
    status: n.CacheNodeStatus,
    az: n.CustomerAvailabilityZone,
    endpoint: n.Endpoint?.Address ? `${n.Endpoint.Address}:${n.Endpoint.Port}` : undefined,
  }));
  const here = `/elasticache/cache?${kind === "serverless" ? "serverless" : kind === "group" ? "id" : "cluster"}=${encodeURIComponent(name)}`;
  const available = status === "available";
  const replicasPerShard = Math.max(0, (shards[0]?.nodes.length ?? 1) - 1);
  const pending = g?.PendingModifiedValues ?? c?.PendingModifiedValues;
  const pendingText = pending
    ? Object.entries(pending)
        .filter(([, v]) => v !== undefined && v !== null && (typeof v !== "object" || Array.isArray(v)))
        .map(([k, v]) => `${k} → ${Array.isArray(v) ? v.join(", ") : String(v)}`)
    : [];

  const [versions, types] = await Promise.all([engineVersions(engine).catch(() => [] as string[]), nodeTypes(engine).catch(() => [] as string[])]);
  const nodeTypeChoices = [...new Set([...(allowed.length ? allowed : types)])].sort();
  const current: Current = {
    nodeType: g?.CacheNodeType ?? c?.CacheNodeType,
    version: s ? s.MajorEngineVersion : first?.EngineVersion,
    retention,
    failover: g?.AutomaticFailover === "enabled",
    multiAz: g?.MultiAZ === "enabled",
    nodes: c?.NumCacheNodes,
    nodeIds: (c?.CacheNodes ?? []).map((n) => n.CacheNodeId!),
    storage: s?.CacheUsageLimits?.DataStorage?.Maximum,
    ecpu: s?.CacheUsageLimits?.ECPUPerSecond?.Maximum,
  };
  const versionChoices = s ? [...new Set(versions.map((v) => v.split(".")[0]))] : versions;
  const modify = (
    <Sheet title={`Modify ${name}`} label="Modify" icon={<SlidersHorizontal size={16} />} testId="modify-cache">
      <ActionForm action={modifyCache.bind(null, kind, name, current)} submit="Modify" testId="modify-cache">
        <Field label="Engine version">
          <select name="version" defaultValue={current.version}>
            {current.version && !versionChoices.includes(current.version) && <option value={current.version}>{current.version}</option>}
            {versionChoices.map((v) => (
              <option key={v} value={v}>
                {v}
                {v === current.version ? " (current)" : ""}
              </option>
            ))}
          </select>
        </Field>
        {kind !== "serverless" && (
          <>
            <Field label="Node type" rule={nodeTypeChoices.length ? { enum: [...nodeTypeChoices, current.nodeType!].filter(Boolean) } : undefined}>
              <input name="nodeType" defaultValue={current.nodeType} list="modify-node-types" autoComplete="off" />
            </Field>
            <datalist id="modify-node-types">
              {nodeTypeChoices.map((t) => (
                <option key={t} value={t} />
              ))}
            </datalist>
          </>
        )}
        {kind === "cluster" && (
          <Field label="Nodes" rule={{ type: "integer", min: 1, max: 40 }}>
            <input name="nodes" type="number" defaultValue={c?.NumCacheNodes} />
          </Field>
        )}
        {kind === "serverless" && (
          <div className="form-row">
            <Field label="Max data storage (GB)" rule={{ type: "integer", min: 1, max: 5000 }}>
              <input name="storage" type="number" defaultValue={current.storage} placeholder="No limit" />
            </Field>
            <Field label="Max ECPU per second" rule={{ type: "integer", min: 1000, max: 15000000 }}>
              <input name="ecpu" type="number" defaultValue={current.ecpu} placeholder="No limit" />
            </Field>
          </div>
        )}
        {!memcached && (
          <Field label="Backup retention (days)" rule={{ type: "integer", min: 0, max: 35 }}>
            <input name="retention" type="number" defaultValue={retention} />
          </Field>
        )}
        {kind === "group" && (
          <div className="form-row">
            <label className="check">
              <input type="checkbox" name="failover" defaultChecked={current.failover} /> Automatic failover
            </label>
            <label className="check">
              <input type="checkbox" name="multiAz" defaultChecked={current.multiAz} /> Multi-AZ
            </label>
          </div>
        )}
        {kind !== "serverless" && (
          <label className="check">
            <input type="checkbox" name="now" defaultChecked /> Apply immediately
          </label>
        )}
      </ActionForm>
    </Sheet>
  );
  const snapNames = snaps.map((x) => x.name);
  const deleteForm = (
    <Sheet title={`Delete ${name}`} label="Delete cache" icon={<Trash2 size={16} />} testId="delete-cache">
      <ActionForm action={deleteCache.bind(null, kind, name)} submit="Delete" tone="danger" confirm={`Delete ${name}?`} testId="delete-cache">
        {!memcached && (
          <>
            <label className="check">
              <input type="checkbox" name="final" /> Create final snapshot
            </label>
            <Field label="Final snapshot name" rule={{ ...SNAPSHOT, required: false }} taken={snapNames} unique>
              <input name="finalName" defaultValue={`${name}-final`} spellCheck={false} />
            </Field>
          </>
        )}
        {memcached && <p className="muted">Memcached keeps no backups: the data goes with the cache.</p>}
      </ActionForm>
    </Sheet>
  );

  const nodeRows = (nodes: Node[]) =>
    nodes.map((n) => ({
      key: `${n.cluster}/${n.nodeId}`,
      icon: <AwsIcon icon={ICONS.cacheNode} size={22} />,
      title: kind === "cluster" ? n.id : n.cluster,
      subtitle: [n.az, n.endpoint].filter(Boolean).join(" · ") || undefined,
      meta: (
        <>
          {n.role && <Pill tone={n.role === "primary" ? "info" : "neutral"}>{n.role}</Pill>}
          {n.status && <Status tone={STATUS_TONE(n.status)}>{n.status}</Status>}
        </>
      ),
      actions: available ? <ActionForm action={rebootNodes.bind(null, n.cluster, [n.nodeId])} submit={`Reboot ${n.cluster}/${n.nodeId}`} icon={<RotateCcw size={15} />} confirm={`Reboot ${n.cluster}?`} /> : undefined,
    }));

  const tabs = [
    ...(kind === "serverless" ? [] : [{ label: clusterMode ? "Shards and nodes" : "Nodes", href: here, active: tab === "nodes" }]),
    { label: "Network and security", href: `${here}&tab=network`, active: tab === "network" || (kind === "serverless" && tab === "nodes") },
    { label: "Maintenance and backups", href: `${here}&tab=backups`, active: tab === "backups", count: snaps.length || undefined },
    { label: "Tags", href: `${here}&tab=tags`, active: tab === "tags", count: tags.length || undefined },
  ];
  const showNetwork = tab === "network" || (kind === "serverless" && tab === "nodes");
  const sgIds = s?.SecurityGroupIds ?? (first?.SecurityGroups ?? []).map((x) => x.SecurityGroupId!);
  const subnetIds = s?.SubnetIds ?? (subnetGroup?.Subnets ?? []).map((x) => x.SubnetIdentifier!);
  const kms = s?.KmsKeyId ?? g?.KmsKeyId;
  const userGroups = s?.UserGroupId ? [s.UserGroupId] : (g?.UserGroupIds ?? []);

  return (
    <Page
      title={name}
      icon={engineIcon(engine)}
      back={back}
      subtitle={s?.ARN ?? g?.ARN ?? c?.ARN}
      actions={
        <>
          {modify}
          {kind === "group" && (
            <Sheet title={clusterMode ? "Shards and replicas" : "Replicas"} label="Resize" icon={<Layers size={16} />} testId="resize-cache">
              <ActionForm action={resizeGroup.bind(null, name, { replicas: replicasPerShard, shards: shards.length, clusterMode })} submit="Apply" testId="resize-cache">
                <div className="form-row">
                  {clusterMode && (
                    <Field label="Shards" rule={{ type: "integer", min: 1, max: 500 }}>
                      <input name="shards" type="number" defaultValue={shards.length} />
                    </Field>
                  )}
                  <Field label="Replicas per shard" rule={{ type: "integer", min: 0, max: 5 }}>
                    <input name="replicas" type="number" defaultValue={replicasPerShard} />
                  </Field>
                </div>
              </ActionForm>
            </Sheet>
          )}
          {!memcached && (
            <Sheet title="Take snapshot" label="Take snapshot" icon={<Camera size={16} />} testId="take-cache-snapshot">
              <ActionForm action={takeSnapshot.bind(null, kind, name)} submit="Take snapshot" testId="take-cache-snapshot">
                <Field label="Snapshot name" rule={SNAPSHOT} generate={{ prefix: `${name}-` }} taken={snapNames} unique>
                  <input name="snapshot" required spellCheck={false} defaultValue={`${name}-${new Date().toISOString().slice(0, 10)}`} />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {kind === "cluster" && available && (
            <ActionForm action={rebootNodes.bind(null, name, cNodes.map((n) => n.nodeId))} submit="Reboot" icon={<RotateCcw size={16} />} confirm={`Reboot every node of ${name}?`} />
          )}
          {deleteForm}
        </>
      }
    >
      <Specs
        items={[
          { label: "Engine", icon: <AwsIcon icon={engineIcon(engine)} size={16} />, value: `${engine} ${version ?? ""}`.trim() },
          { label: "Status", icon: <Database size={15} />, value: <Status tone={STATUS_TONE(status)}>{status ?? ""}</Status> },
          kind === "serverless" && { label: "Deployment", icon: <AwsIcon icon={ICONS.elasticache} size={16} />, value: "Serverless" },
          (g?.CacheNodeType ?? c?.CacheNodeType) && { label: "Node type", icon: <Cpu size={15} />, value: g?.CacheNodeType ?? c?.CacheNodeType },
          g && { label: "Cluster mode", icon: <Layers size={15} />, value: clusterMode ? `${shards.length} shards × ${replicasPerShard + 1} nodes` : `${replicasPerShard + 1} nodes` },
          c && { label: "Nodes", icon: <Layers size={15} />, value: `${c.NumCacheNodes} nodes` },
          g?.MultiAZ === "enabled" && { label: "Multi-AZ", icon: <Shuffle size={15} />, value: "Multi-AZ" },
          tls && { label: "Encryption in transit", icon: <Lock size={15} />, value: "TLS" },
          s?.CacheUsageLimits?.DataStorage?.Maximum && { label: "Storage limit", icon: <Gauge size={15} />, value: `${s.CacheUsageLimits.DataStorage.Maximum} ${s.CacheUsageLimits.DataStorage.Unit}` },
          s?.CacheUsageLimits?.ECPUPerSecond?.Maximum && { label: "ECPU limit", icon: <Gauge size={15} />, value: `${s.CacheUsageLimits.ECPUPerSecond.Maximum.toLocaleString()} ECPU/s` },
        ]}
      />
      {pendingText.length > 0 && (
        <div className="banner" role="status" data-testid="pending-modifications">
          <Clock size={14} /> Pending: {pendingText.join(", ")}
        </div>
      )}
      {host && (
        <Section title="Connect">
          <CodeBlock value={cli} label="Connection command" />
          {s?.ReaderEndpoint?.Address && (
            <div className="muted">
              Reader: <code>{s.ReaderEndpoint.Address}:{s.ReaderEndpoint.Port}</code>
            </div>
          )}
          {!clusterMode &&
            shards[0]?.reader?.Address && (
              <div className="muted">
                Reader: <code>{shards[0].reader.Address}:{shards[0].reader.Port}</code>
              </div>
            )}
        </Section>
      )}
      <Segments label="Cache" items={tabs} />
      {tab === "nodes" && kind === "group" &&
        (clusterMode ? (
          shards.map((sh) => (
            <Section
              key={sh.id}
              title={`Shard ${sh.id}`}
              count={sh.nodes.length}
              plain
              actions={
                available && sh.nodes.length > 1 && g?.AutomaticFailover === "enabled" ? (
                  <ActionForm action={testFailover.bind(null, name, sh.id)} submit={`Test failover ${sh.id}`} icon={<Shuffle size={15} />} confirm={`Promote a replica of shard ${sh.id}?`} />
                ) : undefined
              }
            >
              {sh.slots && <div className="muted">Slots {sh.slots}</div>}
              <List label={`Shard ${sh.id}`} rows={nodeRows(sh.nodes)} />
            </Section>
          ))
        ) : (
          <Section
            title="Nodes"
            count={shards[0]?.nodes.length ?? 0}
            plain
            actions={
              available && (shards[0]?.nodes.length ?? 0) > 1 && g?.AutomaticFailover === "enabled" ? (
                <ActionForm action={testFailover.bind(null, name, shards[0].id)} submit="Test failover" icon={<Shuffle size={15} />} confirm="Promote a replica to primary?" />
              ) : undefined
            }
          >
            <List label="Nodes" rows={nodeRows(shards[0]?.nodes ?? [])} />
          </Section>
        ))}
      {tab === "nodes" && kind === "cluster" && <List label="Nodes" rows={nodeRows(cNodes)} />}
      {showNetwork && (
        <Section>
          <Facts
            items={[
              subnetGroup?.VpcId && ["VPC", <Link key="v" href={`/vpc/${subnetGroup.VpcId}`}>{subnetGroup.VpcId}</Link>],
              first?.CacheSubnetGroupName && ["Subnet group", first.CacheSubnetGroupName],
              subnetIds.length > 0 && ["Subnets", subnetIds.join(", ")],
              sgIds.length > 0 && [
                "Security groups",
                <span key="g" className="chips">
                  {sgIds.map((sg) => (
                    <Link key={sg} href={`/ec2/group?id=${encodeURIComponent(sg)}`}>
                      <Pill icon={<Shield size={12} />}>{sg}</Pill>
                    </Link>
                  ))}
                </span>,
              ],
              first?.PreferredAvailabilityZone && ["Availability Zone", first.PreferredAvailabilityZone],
              ["Encryption in transit", tls ? "Enabled" : <Pill key="t" tone="warn" icon={<TriangleAlert size={12} />}>Disabled</Pill>],
              (s || g?.AtRestEncryptionEnabled || c?.AtRestEncryptionEnabled) && ["Encryption at rest", "Enabled"],
              kms && ["KMS key", <Link key="k" href={`/kms/key?id=${encodeURIComponent(kms)}`}>{shortName(kms)}</Link>],
              g && ["AUTH token", g.AuthTokenEnabled ? "Enabled" : "Disabled"],
              userGroups.length > 0 && ["User groups", userGroups.join(", ")],
              first?.CacheParameterGroup?.CacheParameterGroupName && [
                "Parameter group",
                <span key="p">
                  {first.CacheParameterGroup.CacheParameterGroupName}
                  {first.CacheParameterGroup.ParameterApplyStatus && first.CacheParameterGroup.ParameterApplyStatus !== "in-sync" && <Pill tone="warn">{first.CacheParameterGroup.ParameterApplyStatus}</Pill>}
                </span>,
              ],
              g && ["Automatic failover", g.AutomaticFailover ?? "disabled"],
            ]}
          />
        </Section>
      )}
      {tab === "backups" && (
        <>
          <Section>
            <Facts
              items={[
                !memcached && ["Automatic backups", retention > 0 ? `${retention} days` : <Pill key="b" tone="warn">Disabled</Pill>],
                (s?.DailySnapshotTime ?? g?.SnapshotWindow ?? c?.SnapshotWindow) && ["Backup window", `${s?.DailySnapshotTime ?? g?.SnapshotWindow ?? c?.SnapshotWindow} UTC`],
                first?.PreferredMaintenanceWindow && ["Maintenance window", `${first.PreferredMaintenanceWindow} UTC`],
                first && ["Auto minor version upgrade", first.AutoMinorVersionUpgrade ? "Enabled" : "Disabled"],
                (s?.CreateTime ?? g?.ReplicationGroupCreateTime ?? c?.CacheClusterCreateTime) && ["Created", when(s?.CreateTime ?? g?.ReplicationGroupCreateTime ?? c?.CacheClusterCreateTime)],
              ]}
            />
          </Section>
          {!memcached && (
            <Section title="Snapshots" count={snaps.length} plain>
              <List
                label="Snapshots"
                empty={<Empty>No snapshots</Empty>}
                rows={snaps.map((x) => ({
                  key: x.name,
                  icon: <Camera size={18} />,
                  title: x.name,
                  meta: (
                    <>
                      {x.type && <Pill>{x.type}</Pill>}
                      <Status tone={STATUS_TONE(x.status)}>{x.status ?? ""}</Status>
                      <span>{ago(x.at)}</span>
                    </>
                  ),
                  actions: (
                    <>
                      {x.status === "available" && <RestoreSnapshot snap={x} taken={[name]} types={types} />}
                      {x.status === "available" && <CopySnapshot kind={x.kind} name={x.name} taken={snapNames} />}
                      <ActionForm action={deleteSnapshot.bind(null, x.kind, x.name)} submit={`Delete ${x.name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${x.name}?`} />
                    </>
                  ),
                }))}
              />
            </Section>
          )}
        </>
      )}
      {tab === "tags" && (tags.length ? <Tags tags={tags} /> : <Empty>No tags</Empty>)}
    </Page>
  );
}

