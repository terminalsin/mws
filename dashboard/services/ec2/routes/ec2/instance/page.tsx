import {
  DescribeInstanceAttributeCommand,
  DescribeInstancesCommand,
  DescribeInstanceStatusCommand,
  DescribeSubnetsCommand,
  DescribeVpcsCommand,
  GetConsoleOutputCommand,
  type InstanceAttributeName,
} from "@aws-sdk/client-ec2";
import { ago, load } from "@mws-dashboard/aws";
import { SHELL_ACTIONS } from "@mws-dashboard/aws/shell";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags, type Tone, CopyValue } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { FileExplorer, Terminal } from "@mws-dashboard/ui/console";
import {
  Activity,
  Clock,
  Cpu,
  FolderTree,
  Globe,
  HardDrive,
  KeyRound,
  LayoutDashboard,
  Lock,
  MapPin,
  Network,
  Pencil,
  Play,
  Power,
  RotateCcw,
  ScrollText,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Square,
  SquareTerminal,
  Tag,
  Trash2,
} from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, LINKS, ec2, nameTag } from "../../../lib/clients";
import { STATE_TONE, describeRule, listGroups, listInstanceProfiles, listRules, listTemplates, listVolumes, volumeSpec } from "../../../lib/ec2";
import { TAG_VALUE } from "../../../lib/rules";
import { osIcon } from "../../../lib/views/images";
import {
  CreateImageSheet,
  GroupsSheet,
  MetadataSheet,
  RoleSheet,
  SettingsSheet,
  SnapshotInstanceSheet,
  TemplateFromInstanceSheet,
  type InstanceAttributes,
} from "../../../lib/views/instance-settings";
import { TagsSheet } from "../../../lib/widgets";
import { changeMonitoring, changeState, rename } from "../actions";

type Props = { searchParams: Promise<{ id?: string; tab?: string }> };

export const metadata: Metadata = { title: "Instance" };

const CHECK_TONE: Record<string, Tone> = { ok: "good", impaired: "bad", insufficient_data: "warn", initializing: "warn", "not-applicable": "neutral" };

async function attributes(id: string): Promise<InstanceAttributes> {
  const client = await ec2();
  const get = (Attribute: InstanceAttributeName) => client.send(new DescribeInstanceAttributeCommand({ InstanceId: id, Attribute }));
  const [termination, stop, shutdown, userData] = await Promise.all([
    get("disableApiTermination").then((r) => r.DisableApiTermination?.Value),
    get("disableApiStop").then((r) => r.DisableApiStop?.Value),
    get("instanceInitiatedShutdownBehavior").then((r) => r.InstanceInitiatedShutdownBehavior?.Value),
    get("userData").then((r) => (r.UserData?.Value ? Buffer.from(r.UserData.Value, "base64").toString("utf8") : "")),
  ]);
  return { termination, stop, shutdown, userData };
}

export default async function InstancePage({ searchParams }: Props) {
  const { id = "", tab = "overview" } = await searchParams;
  const back = { href: "/ec2", label: "Instances" };
  const data = await load(async () => {
    const client = await ec2();
    const instance = (await client.send(new DescribeInstancesCommand({ InstanceIds: [id] }))).Reservations?.[0]?.Instances?.[0];
    if (!instance) throw new Error(`The instance ID '${id}' does not exist`);
    return instance;
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.instance} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const i = data.value;
  const client = await ec2();
  const groupIds = (i.SecurityGroups ?? []).map((g) => g.GroupId!);
  // Each read loads on its own: a failure shows where it belongs instead of
  // emptying the page.
  const [volumes, consoleOut, status, attrs, subnet, vpc, profiles, groups, rules, templates] = await Promise.all([
    load(() => listVolumes([{ Name: "attachment.instance-id", Values: [id] }])),
    tab === "logs" ? load(async () => (await client.send(new GetConsoleOutputCommand({ InstanceId: id, Latest: true }))).Output) : null,
    load(async () => (await client.send(new DescribeInstanceStatusCommand({ InstanceIds: [id], IncludeAllInstances: true }))).InstanceStatuses?.[0]),
    load(() => attributes(id)),
    i.SubnetId ? load(async () => (await client.send(new DescribeSubnetsCommand({ SubnetIds: [i.SubnetId!] }))).Subnets?.[0]) : null,
    i.VpcId ? load(async () => (await client.send(new DescribeVpcsCommand({ VpcIds: [i.VpcId!] }))).Vpcs?.[0]) : null,
    load(listInstanceProfiles),
    load(async () => (i.VpcId ? await listGroups([{ Name: "vpc-id", Values: [i.VpcId] }]) : [])),
    tab === "security" && groupIds.length ? load(() => listRules([{ Name: "group-id", Values: groupIds }])) : null,
    load(listTemplates),
  ]);

  const state = i.State?.Name ?? "";
  const name = nameTag(i);
  const gone = state === "terminated" || state === "shutting-down";
  const running = state === "running";
  const here = LINKS.instance(id);
  const target = { service: "ec2" as const, base: `/_aws/ec2/instances/${id}` };
  const profileName = i.IamInstanceProfile?.Arn?.split("/").pop();
  const subnetValue = subnet?.ok ? subnet.value : undefined;
  const vpcValue = vpc?.ok ? vpc.value : undefined;
  const st = status.ok ? status.value : undefined;
  const checks = st && [st.SystemStatus?.Status, st.InstanceStatus?.Status, st.AttachedEbsStatus?.Status].filter((s) => s && s !== "not-applicable");
  const passed = checks?.filter((s) => s === "ok").length ?? 0;
  const failing = checks?.some((s) => s === "impaired");
  const templateId = i.Tags?.find((t) => t.Key === "aws:ec2launchtemplate:id")?.Value;
  const templateVersion = i.Tags?.find((t) => t.Key === "aws:ec2launchtemplate:version")?.Value;
  const tabs = [
    { id: "overview", label: <><LayoutDashboard size={15} aria-hidden /> Details</> },
    { id: "security", label: <><Shield size={15} aria-hidden /> Security</> },
    { id: "networking", label: <><Network size={15} aria-hidden /> Networking</> },
    { id: "storage", label: <><HardDrive size={15} aria-hidden /> Storage</> },
    { id: "tags", label: <><Tag size={15} aria-hidden /> Tags</> },
    ...(running
      ? [
          { id: "terminal", label: <><SquareTerminal size={15} aria-hidden /> Terminal</> },
          { id: "files", label: <><FolderTree size={15} aria-hidden /> Files</> },
        ]
      : []),
    { id: "logs", label: <><ScrollText size={15} aria-hidden /> Logs</> },
  ].map((t) => ({ label: t.label, href: t.id === "overview" ? here : `${here}&tab=${t.id}`, active: tab === t.id }));
  const groupChoices = groups.ok ? groups.value.map((g) => ({ id: g.GroupId!, name: g.GroupName!, vpc: g.VpcId ?? "" })) : [];
  const profileChoices = profiles.ok ? profiles.value.map((p) => ({ name: p.InstanceProfileName!, arn: p.Arn! })) : [];
  const monitored = i.Monitoring?.State === "enabled" || i.Monitoring?.State === "pending";

  return (
    <Page
      title={name ?? id}
      icon={ICONS.instance}
      back={back}
      subtitle={name ? <CopyValue value={id} /> : undefined}
      actions={
        !gone && (
          <>
            <Sheet title="Name" label="Rename" icon={<Pencil size={16} />}>
              <ActionForm action={rename.bind(null, id)} submit="Save">
                <Field label="Name" rule={TAG_VALUE}>
                  <input name="name" defaultValue={name} autoFocus />
                </Field>
              </ActionForm>
            </Sheet>
            {state === "stopped" && <ActionForm action={changeState.bind(null, id, "start")} submit="Start" icon={<Play size={16} />} />}
            {state === "running" && <ActionForm action={changeState.bind(null, id, "reboot")} submit="Reboot" icon={<RotateCcw size={16} />} />}
            {state === "running" && <ActionForm action={changeState.bind(null, id, "stop")} submit="Stop" icon={<Square size={16} />} testId="stop" />}
            {state === "stopping" && <ActionForm action={changeState.bind(null, id, "force-stop")} submit="Force stop" icon={<Square size={16} />} />}
            <SettingsSheet instance={i} attributes={attrs.ok ? attrs.value : {}} />
            <MetadataSheet instance={i} />
            <CreateImageSheet instance={i} />
            <TemplateFromInstanceSheet instance={i} taken={templates.ok ? templates.value.map((t) => t.LaunchTemplateName!) : []} />
            <ActionForm action={changeState.bind(null, id, "terminate")} submit="Terminate" icon={<Trash2 size={16} />} tone="danger" confirm={`Terminate ${id}?`} testId="terminate" />
          </>
        )
      }
    >
      <LiveRefresh when={["pending", "stopping", "shutting-down"].includes(state) || checks?.some((c) => c === "initializing")} />
      <Segments label="Instance" items={tabs} />
      {tab === "terminal" && running && <Terminal target={target} actions={SHELL_ACTIONS} host={i.PrivateDnsName?.split(".")[0] || id} />}
      {tab === "files" && running && <FileExplorer target={target} actions={SHELL_ACTIONS} start="/root" />}
      {tab === "logs" &&
        consoleOut &&
        (consoleOut.ok ? (
          consoleOut.value ? (
            <CodeBlock value={Buffer.from(consoleOut.value, "base64").toString("utf8").split("\n").slice(-1000).join("\n")} label="Console output" />
          ) : (
            <span className="muted">No output yet</span>
          )
        ) : (
          <ErrorNotice error={consoleOut.error} />
        ))}
      {tab === "overview" && (
        <>
          <Specs
            items={[
              { label: "State", icon: <Power size={15} />, value: <Status tone={STATE_TONE[state] ?? "neutral"}>{state}</Status> },
              checks?.length && {
                label: "Status checks",
                icon: failing ? <ShieldAlert size={15} color="var(--bad)" /> : <Activity size={15} />,
                value: <Status tone={failing ? "bad" : passed === checks.length ? "good" : "warn"}>{`${passed}/${checks.length} checks passed`}</Status>,
              },
              { label: "Instance type", icon: <Cpu size={15} />, value: `${i.InstanceType}${i.Architecture ? ` · ${i.Architecture}` : ""}` },
              i.Placement?.AvailabilityZone && { label: "Availability Zone", icon: <MapPin size={15} />, value: i.Placement.AvailabilityZone },
              i.PublicIpAddress && { label: "Public IP", icon: <Globe size={15} />, value: i.PublicIpAddress },
              i.PrivateIpAddress && { label: "Private IP", icon: <Network size={15} />, value: i.PrivateIpAddress },
              { label: "Launched", icon: <Clock size={15} />, value: ago(i.LaunchTime) },
            ]}
          />
          {!status.ok && <ErrorNotice error={status.error} />}
          <Section>
            <Facts
              items={[
                ["Platform", <span key="p" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><AwsIcon icon={osIcon(i.PlatformDetails)} size={14} /> {i.PlatformDetails ?? i.Platform}</span>],
                ["AMI", <Link key="a" href={LINKS.image(i.ImageId!)}>{i.ImageId}</Link>],
                i.VpcId && ["VPC", <Link key="v" href={LINKS.vpc(i.VpcId)}>{(vpcValue && nameTag(vpcValue)) ?? i.VpcId}</Link>],
                i.SubnetId && ["Subnet", <Link key="s" href={LINKS.subnet(i.SubnetId)}>{(subnetValue && nameTag(subnetValue)) ?? i.SubnetId}</Link>],
                i.PublicDnsName && ["Public DNS", <code key="d">{i.PublicDnsName}</code>],
                i.PrivateDnsName && ["Private DNS", <code key="d">{i.PrivateDnsName}</code>],
                i.KeyName && ["Key pair", <span key="k" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}><KeyRound size={13} aria-hidden /> {i.KeyName}</span>],
                profileName && ["IAM role", <Link key="r" href={LINKS.instanceProfile(profileName)}>{profileName}</Link>],
                templateId && ["Launch template", <Link key="t" href={LINKS.template(templateId)}>{templateId}{templateVersion ? ` v${templateVersion}` : ""}</Link>],
                ["Monitoring", (
                  <span key="m" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                    {monitored ? "Detailed" : "Basic"}
                    {!gone && (
                      <ActionForm
                        action={changeMonitoring.bind(null, id, !monitored)}
                        submit={monitored ? "Turn off detailed monitoring" : "Turn on detailed monitoring"}
                        icon={<Activity size={14} />}
                      />
                    )}
                  </span>
                )],
                attrs.ok && ["Termination protection", attrs.value.termination ? <Pill key="t" tone="good" icon={<Lock size={12} />}>on</Pill> : "off"],
                attrs.ok && attrs.value.stop && ["Stop protection", <Pill key="s" tone="good" icon={<Lock size={12} />}>on</Pill>],
                i.MetadataOptions && ["IMDSv2", i.MetadataOptions.HttpTokens === "required" ? "Required" : <Pill key="i" tone="warn">optional</Pill>],
                i.StateReason?.Message && state !== "running" && ["State reason", i.StateReason.Message],
                i.InstanceLifecycle === "spot" && ["Lifecycle", <Pill key="l">spot</Pill>],
              ]}
            />
          </Section>
          {i.Tags?.some((t) => t.Key !== "Name") && <Tags tags={i.Tags.filter((t) => t.Key !== "Name")} />}
        </>
      )}
      {tab === "security" && (
        <>
          <Section
            title="IAM role"
            icon={<AwsIcon icon={ICONS.role} size={16} />}
            actions={!gone && <RoleSheet instance={i} profiles={profileChoices} />}
          >
            {profileName ? <Link href={LINKS.instanceProfile(profileName)}>{profileName}</Link> : <span className="muted">None</span>}
            {!profiles.ok && <ErrorNotice error={profiles.error} />}
          </Section>
          <Section title="Security groups" count={i.SecurityGroups?.length} plain actions={!gone && <GroupsSheet instance={i} groups={groupChoices} />}>
            <List
              label="Security groups"
              rows={(i.SecurityGroups ?? []).map((g) => {
                const mine = rules?.ok ? rules.value.filter((r) => r.GroupId === g.GroupId) : [];
                const described = mine.map((r) => ({ rule: r, ...describeRule(r) }));
                const exposed = described.some((d) => d.exposed);
                return {
                  key: g.GroupId!,
                  icon: exposed ? <ShieldAlert size={20} color="var(--bad)" aria-label="Exposed to the internet" /> : <ShieldCheck size={18} aria-hidden />,
                  title: g.GroupName,
                  subtitle: (
                    <span className="chips">
                      {described.map((d) => (
                        <span key={d.rule.SecurityGroupRuleId} className={d.exposed ? "chip bad" : "chip"}>
                          {d.text}
                        </span>
                      ))}
                    </span>
                  ),
                  href: LINKS.group(g.GroupId!),
                };
              })}
            />
            {rules && !rules.ok && <ErrorNotice error={rules.error} />}
          </Section>
        </>
      )}
      {tab === "networking" && (
        <Section title="Network interfaces" count={i.NetworkInterfaces?.length} plain>
          <List
            label="Network interfaces"
            rows={(i.NetworkInterfaces ?? []).map((n) => ({
              key: n.NetworkInterfaceId!,
              icon: <AwsIcon icon={ICONS.eni} size={22} />,
              title: n.NetworkInterfaceId,
              subtitle: (
                <span>
                  {[
                    `eth${n.Attachment?.DeviceIndex ?? 0}`,
                    n.PrivateIpAddresses?.map((p) => p.PrivateIpAddress).join(", "),
                    n.Association?.PublicIp,
                    n.Ipv6Addresses?.map((a) => a.Ipv6Address).join(", "),
                    n.MacAddress,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                  {n.SubnetId && (
                    <>
                      {" · "}
                      <Link href={LINKS.subnet(n.SubnetId)}>{n.SubnetId}</Link>
                    </>
                  )}
                </span>
              ),
              meta: (
                <>
                  {n.SourceDestCheck === false && <Pill tone="info">no src/dst check</Pill>}
                  {n.Groups?.map((g) => (
                    <Link key={g.GroupId} href={LINKS.group(g.GroupId!)}>
                      <Pill>{g.GroupName}</Pill>
                    </Link>
                  ))}
                </>
              ),
            }))}
          />
        </Section>
      )}
      {tab === "storage" && (
        <Section
          title="Volumes"
          count={volumes.ok ? volumes.value.length : undefined}
          plain
          actions={!gone && volumes.ok && volumes.value.length > 0 && <SnapshotInstanceSheet instance={i} />}
        >
          {volumes.ok ? (
            <List
              label="Volumes"
              rows={volumes.value.map((v) => {
                const a = v.Attachments?.find((x) => x.InstanceId === id);
                return {
                  key: v.VolumeId!,
                  icon: <AwsIcon icon={ICONS.volume} size={22} />,
                  title: `${a?.Device ?? v.VolumeId}${a?.Device === i.RootDeviceName ? " (root)" : ""}`,
                  subtitle: [nameTag(v), v.VolumeId].filter(Boolean).join(" · "),
                  href: LINKS.volume(v.VolumeId!),
                  meta: (
                    <>
                      {v.Encrypted && <Lock size={14} aria-label="Encrypted" />}
                      {a?.DeleteOnTermination === false && <Pill tone="info">kept on terminate</Pill>}
                      <span>{volumeSpec(v)}</span>
                    </>
                  ),
                };
              })}
            />
          ) : (
            <ErrorNotice error={volumes.error} />
          )}
        </Section>
      )}
      {tab === "tags" && (
        <Section title="Tags" count={i.Tags?.length} actions={!gone && <TagsSheet id={id} tags={i.Tags} />}>
          {i.Tags?.length ? <Tags tags={i.Tags} /> : <span className="muted">No tags</span>}
        </Section>
      )}
    </Page>
  );
}
