import { ago, load } from "@mws-dashboard/aws";
import { AwsIcon, Empty, ErrorNotice, List, Metric, Metrics, Page, Pill, Status } from "@mws-dashboard/ui";
import { Terminal } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS } from "../../../lib/clients";
import { SsmNav } from "../../../lib/nav";
import { listNodes, nodeName } from "../../../lib/nodes";
import { tone, words } from "../../../lib/status";

export const metadata: Metadata = { title: "Fleet Manager" };

export default async function Nodes() {
  const nodes = await load(listNodes);
  if (!nodes.ok) {
    return (
      <Page title="Managed nodes" icon={ICONS.ssm}>
        <SsmNav active="nodes" />
        <ErrorNotice error={nodes.error} />
      </Page>
    );
  }
  const list = nodes.value;
  const online = list.filter((n) => n.PingStatus === "Online").length;
  const lost = list.filter((n) => n.PingStatus === "ConnectionLost").length;
  return (
    <Page title="Managed nodes" icon={ICONS.ssm}>
      <SsmNav active="nodes" />
      {list.length > 0 && (
        <Metrics>
          <Metric label="Online" value={online} tone="good" />
          {lost > 0 && <Metric label="Connection lost" value={lost} tone="warn" />}
          <Metric label="Associations failed" value={list.filter((n) => n.AssociationStatus === "Failed").length} />
        </Metrics>
      )}
      <List
        label="Managed nodes"
        empty={<Empty icon={ICONS.node}>EC2 instances launched with an instance profile appear here</Empty>}
        rows={list.map((n) => ({
          key: n.InstanceId!,
          icon: <AwsIcon icon={ICONS.node} size={24} />,
          title: nodeName(n),
          subtitle: [n.InstanceId !== nodeName(n) ? n.InstanceId : null, n.PlatformName && `${n.PlatformName} ${n.PlatformVersion ?? ""}`.trim(), n.IPAddress, n.IamRole && `role ${n.IamRole}`].filter(Boolean).join(" · "),
          href: `/ssm/node?id=${encodeURIComponent(n.InstanceId!)}`,
          meta: (
            <>
              {n.AssociationStatus === "Failed" && <Pill tone="bad">association failed</Pill>}
              {n.IsLatestVersion === false && <Pill>agent {n.AgentVersion}</Pill>}
              <span title="Last ping">{ago(n.LastPingDateTime)}</span>
              <Status tone={tone(n.PingStatus)}>{words(n.PingStatus)}</Status>
            </>
          ),
          actions:
            n.PingStatus === "Online" ? (
              <Link className="icon-button plain" href={`/ssm/commands/send?instance=${encodeURIComponent(n.InstanceId!)}`} aria-label={`Run command on ${nodeName(n)}`} title="Run command">
                <Terminal size={15} />
              </Link>
            ) : undefined,
        }))}
      />
    </Page>
  );
}
