import {
  DescribeInstanceAssociationsStatusCommand,
  DescribeInstanceInformationCommand,
  DescribeInstancePatchStatesCommand,
  DescribeSessionsCommand,
  ListCommandsCommand,
  ListInventoryEntriesCommand,
} from "@aws-sdk/client-ssm";
import { ago, load, when } from "@mws-dashboard/aws";
import { AwsIcon, Empty, ErrorNotice, Facts, List, Page, Pill, Section, Segments, Status, Table } from "@mws-dashboard/ui";
import { Terminal } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../lib/clients";
import { nodeName } from "../../../lib/nodes";
import { tone, words } from "../../../lib/status";

export const metadata: Metadata = { title: "Managed node" };

type Props = { searchParams: Promise<{ id?: string; tab?: string }> };

export default async function Node({ searchParams }: Props) {
  const { id = "", tab = "commands" } = await searchParams;
  const back = { href: "/ssm/nodes", label: "Managed nodes" };
  const data = await load(async () => {
    const c = await ssm();
    const node = (await c.send(new DescribeInstanceInformationCommand({ Filters: [{ Key: "InstanceIds", Values: [id] }] }))).InstanceInformationList?.[0];
    if (!node) throw new Error(`InvalidInstanceId: ${id} is not a managed node`);
    return node;
  });
  if (!data.ok) {
    return (
      <Page title={id || "Managed node"} icon={ICONS.node} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const n = data.value;
  const c = await ssm();
  const base = `/ssm/node?id=${encodeURIComponent(id)}`;
  const tabs = [
    { id: "commands", label: "Run Command" },
    { id: "associations", label: "Associations" },
    { id: "sessions", label: "Sessions" },
    { id: "inventory", label: "Inventory" },
    { id: "patch", label: "Patch" },
  ];
  const active = tabs.some((t) => t.id === tab) ? tab : "commands";

  let body: React.ReactNode = null;
  if (active === "commands") {
    const commands = await load(() => c.send(new ListCommandsCommand({ InstanceId: id, MaxResults: 50 })).then((r) => r.Commands ?? []));
    body = commands.ok ? (
      <List
        label="Commands"
        empty={<Empty icon={ICONS.runCommand}>No commands</Empty>}
        rows={commands.value.map((cmd) => ({
          key: cmd.CommandId!,
          icon: <AwsIcon icon={ICONS.runCommand} size={20} />,
          title: cmd.Comment || cmd.DocumentName,
          subtitle: `${cmd.DocumentName} · ${cmd.CommandId}`,
          href: `/ssm/command?id=${cmd.CommandId}`,
          meta: (
            <>
              <span>{ago(cmd.RequestedDateTime)}</span>
              <Status tone={tone(cmd.Status)}>{words(cmd.Status)}</Status>
            </>
          ),
        }))}
      />
    ) : (
      <ErrorNotice error={commands.error} />
    );
  } else if (active === "associations") {
    const assoc = await load(() => c.send(new DescribeInstanceAssociationsStatusCommand({ InstanceId: id })).then((r) => r.InstanceAssociationStatusInfos ?? []));
    body = assoc.ok ? (
      <List
        label="Associations"
        empty={<Empty icon={ICONS.association}>No associations</Empty>}
        rows={assoc.value.map((a) => ({
          key: a.AssociationId!,
          icon: <AwsIcon icon={ICONS.association} size={20} />,
          title: a.AssociationName || a.Name,
          subtitle: [a.Name, a.ExecutionSummary, a.ErrorCode].filter(Boolean).join(" · "),
          href: `/ssm/association?id=${a.AssociationId}`,
          meta: (
            <>
              {a.ExecutionDate && <span>{ago(a.ExecutionDate)}</span>}
              <Status tone={tone(a.Status)}>{words(a.Status)}</Status>
            </>
          ),
        }))}
      />
    ) : (
      <ErrorNotice error={assoc.error} />
    );
  } else if (active === "sessions") {
    const sessions = await load(async () => {
      const [act, hist] = await Promise.all(
        (["Active", "History"] as const).map((State) => c.send(new DescribeSessionsCommand({ State, Filters: [{ key: "Target", value: id }] })).then((r) => r.Sessions ?? [])),
      );
      return [...act, ...hist];
    });
    body = sessions.ok ? (
      <List
        label="Sessions"
        empty={<Empty icon={ICONS.session}>No sessions</Empty>}
        rows={sessions.value.map((s) => ({
          key: s.SessionId!,
          icon: <AwsIcon icon={ICONS.session} size={20} />,
          title: s.SessionId,
          subtitle: [s.DocumentName, s.Owner?.split("/").pop(), s.Reason].filter(Boolean).join(" · "),
          href: "/ssm/sessions",
          meta: (
            <>
              <span>{ago(s.StartDate)}</span>
              <Status tone={tone(s.Status)}>{words(s.Status)}</Status>
            </>
          ),
        }))}
      />
    ) : (
      <ErrorNotice error={sessions.error} />
    );
  } else if (active === "inventory") {
    const apps = await load(() => c.send(new ListInventoryEntriesCommand({ InstanceId: id, TypeName: "AWS:Application", MaxResults: 50 })).then((r) => r.Entries ?? []));
    body = apps.ok ? (
      <Section title="Applications" count={apps.value.length} plain>
        <Table
          label="Applications"
          rowKey={(e) => `${e.Name}-${e.Version}-${e.Architecture}`}
          empty={<Empty icon="resource/AWSSystemsManagerInventory">No software inventory; an AWS-GatherSoftwareInventory association collects it</Empty>}
          rows={apps.value}
          columns={[
            { header: "Name", cell: (e) => e.Name },
            { header: "Version", cell: (e) => e.Version },
            { header: "Architecture", cell: (e) => e.Architecture },
            { header: "Publisher", cell: (e) => e.Publisher },
          ]}
        />
      </Section>
    ) : (
      <ErrorNotice error={apps.error} />
    );
  } else {
    const patch = await load(() => c.send(new DescribeInstancePatchStatesCommand({ InstanceIds: [id] })).then((r) => r.InstancePatchStates?.[0]));
    body = !patch.ok ? (
      <ErrorNotice error={patch.error} />
    ) : patch.value ? (
      <Facts
        items={[
          ["Operation", `${patch.value.Operation} ${ago(patch.value.OperationEndTime)}`],
          ["Baseline", patch.value.BaselineId],
          patch.value.PatchGroup && ["Patch group", patch.value.PatchGroup],
          ["Installed", patch.value.InstalledCount ?? 0],
          ["Missing", <span key="m" className={patch.value.MissingCount ? "tone-warn" : undefined}>{patch.value.MissingCount ?? 0}</span>],
          ["Failed", <span key="f" className={patch.value.FailedCount ? "tone-bad" : undefined}>{patch.value.FailedCount ?? 0}</span>],
          patch.value.InstalledPendingRebootCount ? ["Pending reboot", patch.value.InstalledPendingRebootCount] : null,
        ]}
      />
    ) : (
      <Empty icon="resource/AWSSystemsManagerPatchManager">Not scanned; run AWS-RunPatchBaseline</Empty>
    );
  }

  return (
    <Page
      title={nodeName(n)}
      icon={ICONS.node}
      back={back}
      subtitle={n.InstanceId}
      actions={
        n.PingStatus === "Online" && (
          <Link className="icon-button primary" href={`/ssm/commands/send?instance=${encodeURIComponent(id)}`} aria-label="Run command" title="Run command">
            <Terminal size={16} />
          </Link>
        )
      }
    >
      <Facts
        items={[
          ["Ping status", <Status key="p" tone={tone(n.PingStatus)}>{words(n.PingStatus)}</Status>],
          n.ResourceType === "EC2Instance" && ["Instance", <Link key="i" href={`/ec2/instance?id=${encodeURIComponent(id)}`}>{id}</Link>],
          n.PlatformName && ["Platform", `${n.PlatformName} ${n.PlatformVersion ?? ""} (${n.PlatformType})`],
          n.IPAddress && ["IP address", n.IPAddress],
          n.ComputerName && ["Computer name", n.ComputerName],
          n.IamRole && ["IAM role", <Link key="r" href={`/iam/roles/${encodeURIComponent(n.IamRole.split("/").pop()!)}`}>{n.IamRole}</Link>],
          n.AgentVersion && ["Agent", `${n.AgentVersion}${n.IsLatestVersion === false ? " (update available)" : ""}`],
          n.LastPingDateTime && ["Last ping", when(n.LastPingDateTime)],
          n.RegistrationDate && ["Registered", when(n.RegistrationDate)],
          n.AssociationStatus && ["Associations", <Pill key="a" tone={tone(n.AssociationStatus)}>{n.AssociationStatus}</Pill>],
        ]}
      />
      <Segments label="Node" items={tabs.map((t) => ({ label: t.label, href: t.id === "commands" ? base : `${base}&tab=${t.id}`, active: t.id === active }))} />
      {body}
    </Page>
  );
}
