import { DescribeImagesCommand, DescribeKeyPairsCommand, DescribeSecurityGroupRulesCommand, DescribeSecurityGroupsCommand, DescribeVpcsCommand, type Instance } from "@aws-sdk/client-ec2";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Metric, Metrics, Page, Pill, Sheet, Status, runtimeIcon } from "@mws-dashboard/ui";
import { KeyRound, Play, Plus, RotateCcw, ShieldAlert, Square, Trash2, X } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ec2, nameTag } from "../../lib/clients";
import { STATE_TONE, describeRule, listInstances } from "../../lib/ec2";
import { COUNT, GROUP_DESCRIPTION, GROUP_NAME, IMAGE, INSTANCE_TYPE, KEY_NAME, PORTS, SOURCE_CIDR, TAG_VALUE } from "../../lib/rules";
import { allowIngress, changeState, createKeyPair, createSecurityGroup, deleteKeyPair, deleteSecurityGroup, launch, revokeIngress } from "./actions";

export const metadata: Metadata = { title: "EC2" };

type Props = { searchParams: Promise<{ tab?: string }> };

const STATES = [
  { id: "running", title: "Running", states: ["running", "pending"] },
  { id: "stopped", title: "Stopped", states: ["stopped", "stopping"] },
  { id: "terminated", title: "Terminated", states: ["terminated", "shutting-down"] },
];

function InstanceActions({ instance }: { instance: Instance }) {
  const state = instance.State?.Name;
  const id = instance.InstanceId!;
  if (state === "terminated" || state === "shutting-down") return null;
  return (
    <>
      {state === "stopped" && <ActionForm action={changeState.bind(null, id, "start")} submit={`Start ${id}`} icon={<Play size={15} />} />}
      {state === "running" && <ActionForm action={changeState.bind(null, id, "reboot")} submit={`Reboot ${id}`} icon={<RotateCcw size={15} />} />}
      {state === "running" && <ActionForm action={changeState.bind(null, id, "stop")} submit={`Stop ${id}`} icon={<Square size={15} />} />}
      <ActionForm action={changeState.bind(null, id, "terminate")} submit={`Terminate ${id}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Terminate ${id}?`} />
    </>
  );
}

/** The OS logo for an image, from its platform details or name. */
function osIcon(text: string | undefined) {
  const t = (text ?? "").toLowerCase();
  const brand = [
    ["ubuntu", "brand/ubuntu"],
    ["debian", "brand/debian"],
    ["red hat", "brand/redhat"],
    ["rhel", "brand/redhat"],
    ["suse", "brand/suse"],
    ["alpine", "brand/alpinelinux"],
    ["amazon linux", "brand/linux"],
    ["al2", "brand/linux"],
    ["linux", "brand/linux"],
  ].find(([k]) => t.includes(k))?.[1];
  return brand ?? runtimeIcon(t) ?? ICONS.ami;
}

export default async function Ec2({ searchParams }: Props) {
  const { tab = "instances" } = await searchParams;
  const client = await ec2();
  const [instances, images, keys, groups] = await Promise.all([
    load(listInstances),
    load(async () => (await client.send(new DescribeImagesCommand({}))).Images ?? []),
    load(async () => (await client.send(new DescribeKeyPairsCommand({}))).KeyPairs ?? []),
    load(async () => (await client.send(new DescribeSecurityGroupsCommand({}))).SecurityGroups ?? []),
  ]);
  const imageList = images.ok ? images.value : [];
  // An image's name stands for its ID: typing one offers the ID.
  const imageRule = {
    ...IMAGE,
    known: imageList.map((i) => i.ImageId!),
    aliases: Object.fromEntries(imageList.filter((i) => i.Name).map((i) => [i.Name!, i.ImageId!])),
  };
  const launchSheet = (
    <Sheet title="Launch instance" label="Launch instance" testId="launch-instance">
      <ActionForm action={launch} submit="Launch" testId="launch-instance">
        <Field label="Name" rule={TAG_VALUE}>
          <input name="name" autoFocus />
        </Field>
        <Field label="Image" rule={imageRule} member="ImageId">
          <input name="image" required list="images" defaultValue={imageList[0]?.ImageId} />
        </Field>
        <datalist id="images">
          {imageList.map((i) => (
            <option key={i.ImageId} value={i.ImageId}>
              {i.Name}
            </option>
          ))}
        </datalist>
        <Field label="Type" rule={INSTANCE_TYPE} member="InstanceType">
          <input name="type" defaultValue="t3.micro" list="types" />
        </Field>
        <datalist id="types">
          {["t3.nano", "t3.micro", "t3.small", "t3.medium", "t4g.micro", "m7g.large", "c7g.large", "r7g.large"].map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
        <Field label="Key pair">
          <select name="keyName" defaultValue="">
            <option value="">—</option>
            {keys.ok && keys.value.map((k) => <option key={k.KeyPairId}>{k.KeyName}</option>)}
          </select>
        </Field>
        <Field label="Security group">
          <select name="securityGroup" defaultValue="">
            <option value="">default</option>
            {groups.ok &&
              groups.value.map((g) => (
                <option key={g.GroupId} value={g.GroupId}>
                  {g.GroupName}
                </option>
              ))}
          </select>
        </Field>
        <Field label="Count" rule={COUNT} member="MaxCount">
          <input name="count" type="number" min={1} max={20} defaultValue={1} />
        </Field>
        <textarea name="userData" rows={4} aria-label="User data" placeholder="#!/bin/bash" className="code-editor" />
      </ActionForm>
    </Sheet>
  );

  let body;
  let actions = launchSheet;
  if (tab === "images") {
    body = images.ok ? (
      <List
        label="Images"
        empty={<Empty icon={ICONS.ami} />}
        rows={images.value.map((i) => ({
          key: i.ImageId!,
          icon: <AwsIcon icon={osIcon(`${i.PlatformDetails} ${i.Name}`)} size={22} />,
          title: i.Name ?? i.ImageId,
          subtitle: i.Description,
          meta: (
            <>
              <Pill>{i.Architecture}</Pill>
              {i.Public === false && <Pill tone="info">private</Pill>}
              <span>{ago(i.CreationDate)}</span>
            </>
          ),
        }))}
      />
    ) : (
      <ErrorNotice error={images.error} />
    );
  } else if (tab === "keys") {
    actions = (
      <Sheet title="New key pair" label="Create key pair" icon={<KeyRound size={16} />} testId="create-key-pair">
        <ActionForm action={createKeyPair} submit="Create" testId="create-key-pair">
          <Field label="Name" rule={KEY_NAME} member="KeyName" taken={keys.ok ? keys.value.map((k) => k.KeyName!) : []} unique>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Type">
            <select name="type" defaultValue="ed25519">
              <option>ed25519</option>
              <option>rsa</option>
            </select>
          </Field>
        </ActionForm>
      </Sheet>
    );
    body = keys.ok ? (
      <List
        label="Key pairs"
        empty={<Empty icon={ICONS.key} />}
        rows={keys.value.map((k) => ({
          key: k.KeyPairId!,
          icon: <KeyRound size={18} />,
          title: k.KeyName,
          subtitle: <code>{k.KeyFingerprint}</code>,
          meta: <Pill>{k.KeyType}</Pill>,
          actions: <ActionForm action={deleteKeyPair.bind(null, k.KeyName!)} submit={`Delete ${k.KeyName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${k.KeyName}?`} />,
        }))}
      />
    ) : (
      <ErrorNotice error={keys.error} />
    );
  } else if (tab === "groups") {
    const [rules, vpcs] = await Promise.all([
      load(async () => (await client.send(new DescribeSecurityGroupRulesCommand({}))).SecurityGroupRules ?? []),
      load(async () => (await client.send(new DescribeVpcsCommand({}))).Vpcs ?? []),
    ]);
    // Names in use in every VPC ("default") are taken whichever VPC is picked;
    // others are checked by EC2 per VPC.
    const vpcIds = vpcs.ok ? vpcs.value.map((v) => v.VpcId) : [];
    const everywhere = [...new Set((groups.ok ? groups.value : []).map((g) => g.GroupName!))].filter((n) =>
      vpcIds.every((v) => groups.ok && groups.value.some((g) => g.GroupName === n && g.VpcId === v)),
    );
    const defaultVpc = vpcs.ok ? vpcs.value.find((v) => v.IsDefault)?.VpcId : undefined;
    actions = (
      <Sheet title="New security group" label="Create security group" testId="create-security-group">
        <ActionForm action={createSecurityGroup} submit="Create" testId="create-security-group">
          <Field label="Name" rule={GROUP_NAME} member="GroupName" taken={everywhere} unique>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Description" rule={GROUP_DESCRIPTION} member="Description">
            <input name="description" />
          </Field>
          <Field label="VPC" member="VpcId">
            <select name="vpc" defaultValue={defaultVpc}>
              {vpcs.ok &&
                vpcs.value.map((v) => (
                  <option key={v.VpcId} value={v.VpcId}>
                    {nameTag(v) ?? v.VpcId}
                    {v.IsDefault ? " (default)" : ""}
                  </option>
                ))}
            </select>
          </Field>
        </ActionForm>
      </Sheet>
    );
    // "anywhere" or a VPC's name stand for their CIDR blocks.
    const cidrRule = {
      ...SOURCE_CIDR,
      aliases: {
        anywhere: "0.0.0.0/0",
        internet: "0.0.0.0/0",
        ...Object.fromEntries((vpcs.ok ? vpcs.value : []).flatMap((v) => (v.CidrBlock ? [[nameTag(v) ?? v.VpcId!, v.CidrBlock]] : []))),
      },
    };
    const inbound = (id: string) => (rules.ok ? rules.value.filter((r) => r.GroupId === id && !r.IsEgress) : []);
    body = groups.ok ? (
      <List
        label="Security groups"
        empty={<Empty icon={ICONS.sg} />}
        rows={groups.value.map((g) => {
          const described = inbound(g.GroupId!).map((r) => ({ rule: r, ...describeRule(r) }));
          const exposed = described.filter((d) => d.exposed);
          return {
            key: g.GroupId!,
            icon: exposed.length ? <ShieldAlert size={20} color="var(--bad)" aria-label="Exposed to the internet" /> : <AwsIcon icon={ICONS.sg} size={22} />,
            title: g.GroupName,
            subtitle: (
              <span className="chips">
                {described.map((d) => (
                  <span key={d.rule.SecurityGroupRuleId} className={d.exposed ? "chip bad" : "chip"}>
                    {d.ports} ← {d.source}
                    <ActionForm action={revokeIngress.bind(null, g.GroupId!, d.rule.SecurityGroupRuleId!)} submit={`Remove ${d.text}`} icon={<X size={11} />} />
                  </span>
                ))}
              </span>
            ),
            meta: <code className="muted">{g.VpcId}</code>,
            actions: (
              <>
                <Sheet title={`Allow inbound · ${g.GroupName}`} label={`Allow inbound to ${g.GroupName}`} icon={<Plus size={15} />}>
                  <ActionForm action={allowIngress.bind(null, g.GroupId!)} submit="Allow">
                    <Field label="Protocol">
                      <select name="protocol" defaultValue="tcp">
                        <option>tcp</option>
                        <option>udp</option>
                        <option value="-1">all</option>
                      </select>
                    </Field>
                    <Field label="Ports" rule={PORTS} member="portRange">
                      <input name="ports" placeholder="443 or 8000-8080" />
                    </Field>
                    <Field label="Source CIDR" rule={cidrRule} member="CidrIp">
                      <input name="cidr" defaultValue="10.0.0.0/8" required />
                    </Field>
                  </ActionForm>
                </Sheet>
                {g.GroupName !== "default" && (
                  <ActionForm action={deleteSecurityGroup.bind(null, g.GroupId!)} submit={`Delete ${g.GroupName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${g.GroupName}?`} />
                )}
              </>
            ),
          };
        })}
      />
    ) : (
      <ErrorNotice error={groups.error} />
    );
  } else {
    body = instances.ok ? (
      <Curated
        label="Instances"
        sections={STATES.map((s) => ({ id: s.id, title: s.title, items: instances.value.filter((i) => s.states.includes(i.State?.Name ?? "")) }))}
        empty={<Empty icon={ICONS.instance} />}
        row={(i) => ({
          key: i.InstanceId!,
          icon: <AwsIcon icon={ICONS.instance} size={24} />,
          title: nameTag(i) ?? i.InstanceId,
          subtitle: [nameTag(i) ? i.InstanceId : null, i.InstanceType, i.PrivateIpAddress].filter(Boolean).join(" · "),
          href: `/ec2/instance?id=${i.InstanceId}`,
          meta: <Status tone={STATE_TONE[i.State?.Name ?? ""] ?? "neutral"}>{i.State?.Name === "running" ? ago(i.LaunchTime) : i.State?.Name}</Status>,
          actions: <InstanceActions instance={i} />,
        })}
      />
    ) : (
      <ErrorNotice error={instances.error} />
    );
  }

  const all = instances.ok ? instances.value : [];
  return (
    <Page title={{ instances: "Instances", images: "Images", keys: "Key pairs", groups: "Security groups" }[tab] ?? "Instances"} actions={actions}>
      {all.length > 0 && (
        <Metrics>
          <Metric label="Running" value={all.filter((i) => i.State?.Name === "running").length} tone="good" />
          <Metric label="Stopped" value={all.filter((i) => i.State?.Name === "stopped").length} />
          <Metric label="vCPUs" value={all.filter((i) => i.State?.Name === "running").reduce((n, i) => n + (i.CpuOptions?.CoreCount ?? 1) * (i.CpuOptions?.ThreadsPerCore ?? 2), 0)} />
        </Metrics>
      )}
      {body}
    </Page>
  );
}
