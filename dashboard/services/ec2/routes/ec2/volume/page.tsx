import { DescribeVolumesModificationsCommand, DescribeVolumeStatusCommand } from "@aws-sdk/client-ec2";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Facts, List, Page, Pill, Section, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { Activity, Clock, Gauge, HardDrive, Lock, MapPin, Power, SlidersHorizontal, Trash2, Unlink } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, LINKS, ec2, nameTag } from "../../../lib/clients";
import { RESOURCE_TONE, listInstances, listSnapshots, listVolumes, volumeSpec } from "../../../lib/ec2";
import { VolumeFields } from "../../../lib/volume-fields";
import { AttachSheet, SnapshotSheet } from "../../../lib/views/volumes";
import { TagsSheet } from "../../../lib/widgets";
import { deleteVolume, detachVolume, modifyVolume } from "../ebs";

type Props = { searchParams: Promise<{ id?: string }> };

export const metadata: Metadata = { title: "Volume" };

const MOD_TONE = { modifying: "warn", optimizing: "warn", completed: "good", failed: "bad" } as const;

export default async function VolumePage({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/ec2?tab=volumes", label: "Volumes" };
  const volume = await load(async () => {
    const v = (await listVolumes([{ Name: "volume-id", Values: [id] }]))[0];
    if (!v) throw new Error(`The volume '${id}' does not exist.`);
    return v;
  });
  if (!volume.ok) {
    return (
      <Page title={id} icon={ICONS.volume} back={back}>
        <ErrorNotice error={volume.error} />
      </Page>
    );
  }
  const v = volume.value;
  const client = await ec2();
  const [mods, health, snapshots, instances] = await Promise.all([
    load(async () => (await client.send(new DescribeVolumesModificationsCommand({ VolumeIds: [id] }))).VolumesModifications ?? []),
    load(async () => (await client.send(new DescribeVolumeStatusCommand({ VolumeIds: [id] }))).VolumeStatuses?.[0]),
    load(() => listSnapshots([{ Name: "volume-id", Values: [id] }])),
    load(() => listInstances()),
  ]);
  const mod = mods.ok ? mods.value.sort((a, b) => String(b.StartTime).localeCompare(String(a.StartTime)))[0] : undefined;
  const modifying = mod && (mod.ModificationState === "modifying" || mod.ModificationState === "optimizing");
  const healthStatus = health.ok ? health.value?.VolumeStatus?.Status : undefined;
  const instanceList = instances.ok ? instances.value : [];
  const instanceName = (iid?: string) => {
    const i = instanceList.find((x) => x.InstanceId === iid);
    return (i && nameTag(i)) ?? iid;
  };
  const name = nameTag(v);
  const current = { size: v.Size, type: v.VolumeType, iops: v.Iops, throughput: v.Throughput };
  const transit = ["creating", "deleting"].includes(v.State ?? "") || v.Attachments?.some((a) => a.State !== "attached") || modifying;
  return (
    <Page
      title={name ?? id}
      icon={ICONS.volume}
      back={back}
      subtitle={name ? id : undefined}
      actions={
        <>
          {v.State === "available" && <AttachSheet volume={v} instances={instanceList} />}
          {v.State === "in-use" &&
            v.Attachments?.map((a) => (
              <ActionForm
                key={a.InstanceId}
                action={detachVolume.bind(null, id, false)}
                submit={`Detach from ${a.InstanceId}`}
                icon={<Unlink size={16} />}
                confirm={`Detach ${id} from ${a.InstanceId}? Unmount it first.`}
                testId="detach-volume"
              />
            ))}
          {(v.State === "available" || v.State === "in-use") && !modifying && (
            <Sheet title="Modify volume" label="Modify volume" icon={<SlidersHorizontal size={16} />} testId="modify-volume">
              <ActionForm action={modifyVolume.bind(null, id, current)} submit="Modify" testId="modify-volume">
                <VolumeFields type={v.VolumeType} size={v.Size} iops={v.Iops} throughput={v.Throughput} minSize={v.Size} />
              </ActionForm>
            </Sheet>
          )}
          {(v.State === "available" || v.State === "in-use") && <SnapshotSheet volume={v} />}
          {v.State === "available" && (
            <ActionForm action={deleteVolume.bind(null, id, "/ec2?tab=volumes")} submit="Delete" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${id}? Its data is lost.`} testId="delete-volume" />
          )}
        </>
      }
    >
      <LiveRefresh when={!!transit} />
      <Specs
        items={[
          { label: "State", icon: <Power size={15} />, value: <Status tone={RESOURCE_TONE[v.State ?? ""] ?? "neutral"}>{v.State ?? ""}</Status> },
          healthStatus && healthStatus !== "ok" && { label: "Volume status", icon: <Activity size={15} />, value: <Status tone={healthStatus === "impaired" ? "bad" : "warn"}>{healthStatus}</Status> },
          { label: "Size and type", icon: <HardDrive size={15} />, value: volumeSpec(v) },
          { label: "Availability Zone", icon: <MapPin size={15} />, value: v.AvailabilityZone },
          v.Encrypted && { label: "Encrypted", icon: <Lock size={15} />, value: v.KmsKeyId ? <Link href={LINKS.kms(v.KmsKeyId)}>{v.KmsKeyId.split("/").pop()}</Link> : "encrypted" },
          { label: "Created", icon: <Clock size={15} />, value: ago(v.CreateTime) },
        ]}
      />
      {mod && (
        <Section title="Modification" icon={<Gauge size={16} aria-hidden />}>
          <Facts
            items={[
              ["State", <Status key="s" tone={MOD_TONE[mod.ModificationState as keyof typeof MOD_TONE] ?? "neutral"}>{mod.ModificationState ?? ""}</Status>],
              mod.Progress !== undefined && modifying && ["Progress", `${mod.Progress}%`],
              ["Change", `${mod.OriginalSize} → ${mod.TargetSize} GiB · ${mod.OriginalVolumeType} → ${mod.TargetVolumeType}`],
              mod.TargetIops !== undefined && mod.TargetIops !== mod.OriginalIops && ["IOPS", `${mod.OriginalIops} → ${mod.TargetIops}`],
              mod.StatusMessage && ["Message", mod.StatusMessage],
              ["Started", ago(mod.StartTime)],
            ]}
          />
        </Section>
      )}
      <Section title="Attachments" count={v.Attachments?.length ?? 0} plain>
        <List
          label="Attachments"
          rows={(v.Attachments ?? []).map((a) => ({
            key: `${a.InstanceId}${a.Device}`,
            icon: <AwsIcon icon={ICONS.instance} size={22} />,
            title: instanceName(a.InstanceId),
            subtitle: [a.InstanceId, a.Device].filter(Boolean).join(" · "),
            href: a.InstanceId ? LINKS.instance(a.InstanceId) : undefined,
            meta: (
              <>
                {a.DeleteOnTermination && <Pill>deleted with instance</Pill>}
                <Status tone={a.State === "attached" ? "good" : "warn"}>{a.State ?? ""}</Status>
              </>
            ),
          }))}
        />
      </Section>
      {v.SnapshotId && (
        <Facts items={[["Created from", <span key="s">{v.SnapshotId}</span>]]} />
      )}
      <Section title="Snapshots" count={snapshots.ok ? snapshots.value.length : undefined} plain>
        {snapshots.ok ? (
          <List
            label="Snapshots"
            rows={snapshots.value.map((s) => ({
              key: s.SnapshotId!,
              icon: <AwsIcon icon={ICONS.snapshot} size={22} />,
              title: nameTag(s) ?? s.SnapshotId,
              subtitle: [nameTag(s) ? s.SnapshotId : null, s.Description].filter(Boolean).join(" · "),
              href: "/ec2?tab=snapshots",
              meta: (
                <>
                  <Status tone={RESOURCE_TONE[s.State ?? ""] ?? "neutral"}>{s.State ?? ""}</Status>
                  <span>{ago(s.StartTime)}</span>
                </>
              ),
            }))}
          />
        ) : (
          <ErrorNotice error={snapshots.error} />
        )}
      </Section>
      {v.Tags?.length ? (
        <Section title="Tags" count={v.Tags.length} actions={<TagsSheet id={id} tags={v.Tags} />}>
          <Tags tags={v.Tags} />
        </Section>
      ) : (
        <Section title="Tags" actions={<TagsSheet id={id} tags={[]} />}>
          <span className="muted">No tags</span>
        </Section>
      )}
    </Page>
  );
}
