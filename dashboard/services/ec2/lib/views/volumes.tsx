import "server-only";

import { DescribeAvailabilityZonesCommand, type Instance, type Snapshot, type Volume } from "@aws-sdk/client-ec2";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Metric, Metrics, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { Camera, Link2, Lock, Plus, Trash2, Unlink } from "lucide-react";

import { attachVolume, createSnapshot, createVolume, deleteVolume, detachVolume } from "../../routes/ec2/ebs";
import { ICONS, LINKS, ec2, nameTag } from "../clients";
import { RESOURCE_TONE, listInstances, listSnapshots, listVolumes, volumeSpec } from "../ec2";
import { DEVICE, SNAPSHOT_DESCRIPTION, TAG_VALUE } from "../rules";
import { VolumeFields } from "../volume-fields";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { ResourcePicker } from "@mws-dashboard/ui/pickers";

export async function zones() {
  return ((await (await ec2()).send(new DescribeAvailabilityZonesCommand({}))).AvailabilityZones ?? []).map((z) => z.ZoneName!);
}

/** The "Create volume" form, optionally from a snapshot or in a zone. */
export function CreateVolumeSheet({ zones, snapshots, snapshot, zone }: { zones: string[]; snapshots: Snapshot[]; snapshot?: Snapshot; zone?: string }) {
  return (
    <Sheet title={snapshot ? `Volume from ${snapshot.SnapshotId}` : "Create volume"} label={snapshot ? `Create volume from ${snapshot.SnapshotId}` : "Create volume"} icon={snapshot ? <Plus size={15} /> : undefined} testId={snapshot ? undefined : "create-volume"}>
      <ActionForm action={createVolume} submit="Create" testId={snapshot ? undefined : "create-volume"}>
        <Field label="Name" rule={TAG_VALUE}>
          <input name="name" autoFocus />
        </Field>
        <Field label="Availability Zone" member="AvailabilityZone">
          <select name="zone" defaultValue={zone ?? zones[0]} required>
            {zones.map((z) => (
              <option key={z}>{z}</option>
            ))}
          </select>
        </Field>
        {snapshot ? (
          <input type="hidden" name="snapshot" value={snapshot.SnapshotId} />
        ) : (
          snapshots.length > 0 && (
            <Field label="Snapshot" member="SnapshotId">
              <select name="snapshot" defaultValue="">
                <option value="">None</option>
                {snapshots
                  .filter((s) => s.State === "completed")
                  .map((s) => (
                    <option key={s.SnapshotId} value={s.SnapshotId}>
                      {nameTag(s) ?? s.SnapshotId} · {s.VolumeSize} GiB
                    </option>
                  ))}
              </select>
            </Field>
          )
        )}
        <VolumeFields size={snapshot ? undefined : 8} minSize={snapshot?.VolumeSize} optionalSize={!!snapshot} />
        <MoreFields label="Encryption">
          <label className="check">
            <input type="checkbox" name="encrypted" defaultChecked={snapshot?.Encrypted} /> Encrypted
          </label>
          <Field label="KMS key" member="KmsKeyId" hint="Blank: aws/ebs">
            <ResourcePicker kind="kms-key" name="kmsKey" placeholder="alias/aws/ebs" />
          </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
}

/** "Attach volume": instances in the volume's zone, and a free device name. */
export function AttachSheet({ volume, instances }: { volume: Volume; instances: Instance[] }) {
  const id = volume.VolumeId!;
  const candidates = instances.filter((i) => i.Placement?.AvailabilityZone === volume.AvailabilityZone && ["running", "stopped"].includes(i.State?.Name ?? ""));
  const device = (i: Instance) => new Set((i.BlockDeviceMappings ?? []).map((b) => b.DeviceName));
  const used = new Set(candidates.flatMap((i) => [...device(i)]).filter((d): d is string => !!d));
  const free = (DEVICE.known ?? []).filter((d) => !used.has(d));
  return (
    <Sheet title={`Attach ${nameTag(volume) ?? id}`} label={`Attach ${id}`} icon={<Link2 size={15} />} testId="attach-volume">
      <ActionForm action={attachVolume.bind(null, id)} submit="Attach" testId="attach-volume">
        <Field label="Instance" member="InstanceId" hint={volume.AvailabilityZone}>
          <select name="instance" required>
            {candidates.map((i) => (
              <option key={i.InstanceId} value={i.InstanceId}>
                {nameTag(i) ?? i.InstanceId} · {i.State?.Name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Device name" rule={{ ...DEVICE, known: free, taken: [...used] }} member="Device">
          <input name="device" defaultValue={free[0] ?? "/dev/sdf"} required />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

export function SnapshotSheet({ volume }: { volume: Volume }) {
  const id = volume.VolumeId!;
  return (
    <Sheet title={`Snapshot ${nameTag(volume) ?? id}`} label={`Create snapshot of ${id}`} icon={<Camera size={15} />} testId="create-snapshot">
      <ActionForm action={createSnapshot.bind(null, id)} submit="Create" testId="create-snapshot">
        <Field label="Name" rule={TAG_VALUE}>
          <input name="name" autoFocus defaultValue={nameTag(volume)} />
        </Field>
        <Field label="Description" rule={SNAPSHOT_DESCRIPTION} member="Description">
          <input name="description" />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

/** A volume's row actions, as on AWS's Actions menu. */
export function VolumeActions({ volume, instances }: { volume: Volume; instances: Instance[] }) {
  const id = volume.VolumeId!;
  const state = volume.State;
  return (
    <>
      {state === "available" && <AttachSheet volume={volume} instances={instances} />}
      {state === "in-use" &&
        volume.Attachments?.map((a) => (
          <ActionForm
            key={a.InstanceId}
            action={detachVolume.bind(null, id, false)}
            submit={`Detach ${id} from ${a.InstanceId}`}
            icon={<Unlink size={15} />}
            confirm={`Detach ${id} from ${a.InstanceId}? Unmount it first.`}
          />
        ))}
      {(state === "available" || state === "in-use") && <SnapshotSheet volume={volume} />}
      {state === "available" && <ActionForm action={deleteVolume.bind(null, id, undefined)} submit={`Delete ${id}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${id}? Its data is lost.`} />}
    </>
  );
}

export async function VolumesView() {
  const [volumes, instances, snapshots, zoneList] = await Promise.all([load(() => listVolumes()), load(() => listInstances()), load(() => listSnapshots()), load(zones)]);
  const instanceList = instances.ok ? instances.value : [];
  const instanceName = (id?: string) => {
    const i = instanceList.find((x) => x.InstanceId === id);
    return (i && nameTag(i)) ?? id;
  };
  const actions = <CreateVolumeSheet zones={zoneList.ok ? zoneList.value : []} snapshots={snapshots.ok ? snapshots.value : []} />;
  if (!volumes.ok) return { body: <ErrorNotice error={volumes.error} />, actions };
  const list = volumes.value.sort((a, b) => String(b.CreateTime).localeCompare(String(a.CreateTime)));
  const available = list.filter((v) => v.State === "available");
  const body = (
    <>
      {list.length > 0 && (
        <Metrics>
          <Metric label="In use" value={list.filter((v) => v.State === "in-use").length} tone="good" />
          <Metric label="Available" value={available.length} tone={available.length ? "warn" : undefined} />
          <Metric label="GiB" value={list.reduce((n, v) => n + (v.Size ?? 0), 0)} />
        </Metrics>
      )}
      <List
        label="Volumes"
        empty={<Empty icon={ICONS.volume} />}
        rows={list.map((v) => {
          const attachment = v.Attachments?.[0];
          return {
            key: v.VolumeId!,
            icon: <AwsIcon icon={ICONS.volume} size={22} />,
            title: nameTag(v) ?? v.VolumeId,
            // The row links to the volume, so the instance is named, not linked.
            subtitle: [nameTag(v) ? v.VolumeId : null, volumeSpec(v), v.AvailabilityZone, attachment?.InstanceId && `${instanceName(attachment.InstanceId)} ${attachment.Device ?? ""}`.trim()]
              .filter(Boolean)
              .join(" · "),
            href: LINKS.volume(v.VolumeId!),
            meta: (
              <>
                {v.Encrypted && <Lock size={14} aria-label="Encrypted" />}
                {v.SnapshotId && <Pill title={`From ${v.SnapshotId}`}>snapshot</Pill>}
                <Status tone={RESOURCE_TONE[attachment?.State && attachment.State !== "attached" ? "pending" : (v.State ?? "")] ?? "neutral"}>
                  {attachment?.State && attachment.State !== "attached" ? attachment.State : (v.State ?? "")}
                </Status>
                <span>{ago(v.CreateTime)}</span>
              </>
            ),
            actions: <VolumeActions volume={v} instances={instanceList} />,
          };
        })}
      />
    </>
  );
  return { body, actions };
}
