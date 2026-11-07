import { DescribeCacheClustersCommand, DescribeReplicationGroupsCommand, DescribeServerlessCachesCommand } from "@aws-sdk/client-elasticache";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, List, Page, Pill, Section, Specs, Status } from "@mws-dashboard/ui";
import { Cpu, Database, Gauge, Lock, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, elasticache, engineIcon } from "../../../lib/clients";
import { deleteCache } from "../actions";

export const metadata: Metadata = { title: "Cache" };

type Props = { searchParams: Promise<{ id?: string; serverless?: string; cluster?: string }> };

export default async function CachePage({ searchParams }: Props) {
  const { id, serverless, cluster } = await searchParams;
  const kind = serverless ? "serverless" : id ? "group" : "cluster";
  const name = serverless ?? id ?? cluster ?? "";
  const back = { href: "/elasticache", label: "Caches" };
  const data = await load(async () => {
    const client = await elasticache();
    if (serverless) {
      const s = (await client.send(new DescribeServerlessCachesCommand({ ServerlessCacheName: serverless }))).ServerlessCaches![0];
      return { engine: s.Engine!, status: s.Status, endpoint: s.Endpoint, reader: s.ReaderEndpoint, tls: true, arn: s.ARN, limits: s.CacheUsageLimits, nodes: [] as { id: string; role?: string; status?: string; az?: string }[], nodeType: undefined as string | undefined };
    }
    if (id) {
      const g = (await client.send(new DescribeReplicationGroupsCommand({ ReplicationGroupId: id }))).ReplicationGroups![0];
      const ep = g.ConfigurationEndpoint ?? g.NodeGroups?.[0]?.PrimaryEndpoint;
      return {
        engine: g.Engine!,
        status: g.Status,
        endpoint: ep,
        reader: g.NodeGroups?.[0]?.ReaderEndpoint,
        tls: g.TransitEncryptionEnabled,
        arn: g.ARN,
        limits: undefined,
        nodeType: g.CacheNodeType,
        nodes: (g.NodeGroups ?? []).flatMap((n) => (n.NodeGroupMembers ?? []).map((m) => ({ id: m.CacheClusterId!, role: m.CurrentRole, status: undefined, az: m.PreferredAvailabilityZone }))),
      };
    }
    const c = (await client.send(new DescribeCacheClustersCommand({ CacheClusterId: cluster, ShowCacheNodeInfo: true }))).CacheClusters![0];
    return {
      engine: c.Engine!,
      status: c.CacheClusterStatus,
      endpoint: c.ConfigurationEndpoint ?? c.CacheNodes?.[0]?.Endpoint,
      reader: undefined,
      tls: c.TransitEncryptionEnabled,
      arn: c.ARN,
      limits: undefined,
      nodeType: c.CacheNodeType,
      nodes: (c.CacheNodes ?? []).map((n) => ({ id: n.CacheNodeId!, role: undefined, status: n.CacheNodeStatus, az: n.CustomerAvailabilityZone })),
    };
  });
  if (!data.ok) {
    return (
      <Page title={name} icon={ICONS.elasticache} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const d = data.value;
  const host = d.endpoint?.Address;
  const cli = d.engine === "memcached" ? `telnet ${host} ${d.endpoint?.Port}` : `${d.engine === "valkey" ? "valkey-cli" : "redis-cli"} -h ${host} -p ${d.endpoint?.Port}${d.tls ? " --tls" : ""}${kind !== "cluster" && d.engine !== "memcached" && kind === "serverless" ? " -c" : ""}`;
  return (
    <Page
      title={name}
      icon={engineIcon(d.engine)}
      back={back}
      subtitle={d.arn}
      actions={<ActionForm action={deleteCache.bind(null, kind, name)} submit="Delete cache" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}?`} testId="delete-cache" />}
    >
      <Specs
        items={[
          { label: "Engine", icon: <AwsIcon icon={engineIcon(d.engine)} size={16} />, value: d.engine },
          { label: "Status", icon: <Database size={15} />, value: <Status tone={STATUS_TONE(d.status)}>{d.status}</Status> },
          kind === "serverless" && { label: "Deployment", icon: <AwsIcon icon={ICONS.elasticache} size={16} />, value: "Serverless" },
          d.nodeType && { label: "Node type", icon: <Cpu size={15} />, value: d.nodeType },
          d.tls && { label: "Encryption in transit", icon: <Lock size={15} />, value: "TLS" },
          d.limits?.DataStorage?.Maximum && { label: "Storage limit", icon: <Gauge size={15} />, value: `${d.limits.DataStorage.Maximum} ${d.limits.DataStorage.Unit}` },
        ]}
      />
      {host && (
        <Section title="Connect">
          <CodeBlock value={cli} label="Connection command" />
          {d.reader?.Address && (
            <div className="muted">
              Reader: <code>{d.reader.Address}:{d.reader.Port}</code>
            </div>
          )}
        </Section>
      )}
      {d.nodes.length > 0 && (
        <Section title="Nodes" count={d.nodes.length} plain>
          <List
            label="Nodes"
            rows={d.nodes.map((n) => ({
              key: n.id,
              icon: <AwsIcon icon={ICONS.cacheNode} size={22} />,
              title: n.id,
              subtitle: n.az,
              meta: (
                <>
                  {n.role && <Pill tone={n.role === "primary" ? "info" : "neutral"}>{n.role}</Pill>}
                  {n.status && <Status tone={STATUS_TONE(n.status)}>{n.status}</Status>}
                </>
              ),
            }))}
          />
        </Section>
      )}
    </Page>
  );
}
