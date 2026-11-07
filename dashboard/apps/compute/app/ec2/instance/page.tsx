import { DescribeInstancesCommand, DescribeVolumesCommand, GetConsoleOutputCommand } from "@aws-sdk/client-ec2";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Field, List, Page, Section, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { Clock, Cpu, Globe, HardDrive, KeyRound, Network, Pencil, Play, Power, RotateCcw, Shield, Square, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ec2, nameTag } from "../../../lib/clients";
import { STATE_TONE } from "../../../lib/ec2";
import { changeState, rename } from "../actions";

type Props = { searchParams: Promise<{ id?: string }> };

export const metadata: Metadata = { title: "Instance" };

export default async function InstancePage({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/ec2", label: "Instances" };
  const data = await load(async () => {
    const client = await ec2();
    const instance = (await client.send(new DescribeInstancesCommand({ InstanceIds: [id] }))).Reservations?.[0]?.Instances?.[0];
    if (!instance) throw new Error(`The instance ID '${id}' does not exist`);
    const [volumes, console] = await Promise.all([
      client.send(new DescribeVolumesCommand({ Filters: [{ Name: "attachment.instance-id", Values: [id] }] })).then((r) => r.Volumes ?? [], () => []),
      client.send(new GetConsoleOutputCommand({ InstanceId: id, Latest: true })).then((r) => (r.Output ? Buffer.from(r.Output, "base64").toString("utf8") : ""), () => ""),
    ]);
    return { instance, volumes, console };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.instance} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { instance: i, volumes, console } = data.value;
  const state = i.State?.Name ?? "";
  const name = nameTag(i);
  const gone = state === "terminated" || state === "shutting-down";
  return (
    <Page
      title={name ?? id}
      icon={ICONS.instance}
      back={back}
      subtitle={name ? id : undefined}
      actions={
        !gone && (
          <>
            <Sheet title="Name" label="Rename" icon={<Pencil size={16} />}>
              <ActionForm action={rename.bind(null, id)} submit="Save">
                <Field label="Name">
                  <input name="name" defaultValue={name} />
                </Field>
              </ActionForm>
            </Sheet>
            {state === "stopped" && <ActionForm action={changeState.bind(null, id, "start")} submit="Start" icon={<Play size={16} />} />}
            {state === "running" && <ActionForm action={changeState.bind(null, id, "reboot")} submit="Reboot" icon={<RotateCcw size={16} />} />}
            {state === "running" && <ActionForm action={changeState.bind(null, id, "stop")} submit="Stop" icon={<Square size={16} />} />}
            <ActionForm action={changeState.bind(null, id, "terminate")} submit="Terminate" icon={<Trash2 size={16} />} tone="danger" confirm={`Terminate ${id}?`} testId="terminate" />
          </>
        )
      }
    >
      <Specs
        items={[
          { label: "State", icon: <Power size={15} />, value: <Status tone={STATE_TONE[state] ?? "neutral"}>{state}</Status> },
          { label: "Instance type", icon: <Cpu size={15} />, value: i.InstanceType },
          i.PrivateIpAddress && { label: "Private IP", icon: <Network size={15} />, value: i.PrivateIpAddress },
          i.PublicIpAddress && { label: "Public IP", icon: <Globe size={15} />, value: i.PublicIpAddress },
          { label: "Image", icon: <AwsIcon icon="resource/AmazonEC2AMI" size={16} />, value: i.ImageId },
          i.KeyName && { label: "Key pair", icon: <KeyRound size={15} />, value: i.KeyName },
          i.IamInstanceProfile?.Arn && {
            label: "Instance profile",
            icon: <AwsIcon icon="resource/AWSIdentityAccessManagementRole" size={16} />,
            value: <a href={`/security/iam/roles/${encodeURIComponent(i.IamInstanceProfile.Arn.split("/").pop() ?? "")}`}>{i.IamInstanceProfile.Arn.split("/").pop()}</a>,
          },
          i.SecurityGroups?.length && { label: "Security groups", icon: <Shield size={15} />, value: i.SecurityGroups.map((g) => g.GroupName).join(", ") },
          { label: "Launched", icon: <Clock size={15} />, value: ago(i.LaunchTime) },
        ]}
      />
      {i.Tags?.some((t) => t.Key !== "Name") && <Tags tags={i.Tags.filter((t) => t.Key !== "Name")} />}
      {volumes.length > 0 && (
        <Section title="Volumes" count={volumes.length} plain>
          <List
            label="Volumes"
            rows={volumes.map((v) => ({
              key: v.VolumeId!,
              icon: <HardDrive size={18} />,
              title: v.Attachments?.find((a) => a.InstanceId === id)?.Device ?? v.VolumeId,
              subtitle: v.VolumeId,
              meta: (
                <span>
                  {v.Size} GiB · {v.VolumeType}
                  {v.Encrypted ? " · encrypted" : ""}
                </span>
              ),
            }))}
          />
        </Section>
      )}
      {console && (
        <Section title="Console" icon={<AwsIcon icon={ICONS.instance} size={16} />}>
          <CodeBlock value={console.split("\n").slice(-200).join("\n")} label="Console output" />
        </Section>
      )}
    </Page>
  );
}
