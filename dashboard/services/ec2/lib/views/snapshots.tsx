import "server-only";

import { DescribeRegionsCommand, type Snapshot } from "@aws-sdk/client-ec2";
import { ago, load, region } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Sheet, Status } from "@mws-dashboard/ui";
import { Copy, Lock, Trash2 } from "lucide-react";
import Link from "next/link";

import { copySnapshot, deleteSnapshot } from "../../routes/ec2/ebs";
import { ICONS, LINKS, ec2, nameTag } from "../clients";
import { RESOURCE_TONE, listSnapshots } from "../ec2";
import { SNAPSHOT_DESCRIPTION, TAG_VALUE } from "../rules";
import { CreateVolumeSheet, zones } from "./volumes";

export async function regions() {
  return ((await (await ec2()).send(new DescribeRegionsCommand({}))).Regions ?? []).map((r) => r.RegionName!).sort();
}

export function CopySnapshotSheet({ snapshot, regions, here }: { snapshot: Snapshot; regions: string[]; here: string }) {
  const id = snapshot.SnapshotId!;
  return (
    <Sheet title={`Copy ${id}`} label={`Copy ${id}`} icon={<Copy size={15} />} testId="copy-snapshot">
      <ActionForm action={copySnapshot.bind(null, id)} submit="Copy" testId="copy-snapshot">
        <Field label="Name" rule={TAG_VALUE}>
          <input name="name" defaultValue={nameTag(snapshot)} autoFocus />
        </Field>
        <Field label="Description" rule={SNAPSHOT_DESCRIPTION} member="Description">
          <input name="description" defaultValue={`Copy of ${id}`} />
        </Field>
        <Field label="Destination Region" member="DestinationRegion">
          <select name="region" defaultValue={here}>
            {regions.map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </Field>
        <label className="check">
          <input type="checkbox" name="encrypted" defaultChecked={snapshot.Encrypted} disabled={snapshot.Encrypted} /> Encrypt
        </label>
        <Field label="KMS key" member="KmsKeyId" hint="Blank: aws/ebs">
          <input name="kmsKey" />
        </Field>
      </ActionForm>
    </Sheet>
  );
}

export async function SnapshotsView() {
  const [snapshots, zoneList, regionList, here] = await Promise.all([load(() => listSnapshots()), load(zones), load(regions), region()]);
  const zonesNow = zoneList.ok ? zoneList.value : [];
  const regionsNow = regionList.ok ? regionList.value : [here];
  if (!snapshots.ok) return { body: <ErrorNotice error={snapshots.error} /> };
  const body = (
    <List
      label="Snapshots"
      empty={<Empty icon={ICONS.snapshot} />}
      rows={snapshots.value
        .sort((a, b) => String(b.StartTime).localeCompare(String(a.StartTime)))
        .map((s) => ({
          key: s.SnapshotId!,
          icon: <AwsIcon icon={ICONS.snapshot} size={22} />,
          title: nameTag(s) ?? s.SnapshotId,
          subtitle: (
            <span>
              {[nameTag(s) ? s.SnapshotId : null, `${s.VolumeSize} GiB`, s.Description].filter(Boolean).join(" · ")}
              {s.VolumeId && s.VolumeId !== "vol-ffffffff" && (
                <>
                  {" · "}
                  <Link href={LINKS.volume(s.VolumeId)}>{s.VolumeId}</Link>
                </>
              )}
            </span>
          ),
          meta: (
            <>
              {s.Encrypted && <Lock size={14} aria-label="Encrypted" />}
              {s.State === "pending" && s.Progress && <span>{s.Progress}</span>}
              <Status tone={RESOURCE_TONE[s.State ?? ""] ?? "neutral"}>{s.State ?? ""}</Status>
              <span>{ago(s.StartTime)}</span>
            </>
          ),
          actions: s.State === "completed" && (
            <>
              <CreateVolumeSheet zones={zonesNow} snapshots={[]} snapshot={s} />
              <CopySnapshotSheet snapshot={s} regions={regionsNow} here={here} />
              <ActionForm action={deleteSnapshot.bind(null, s.SnapshotId!)} submit={`Delete ${s.SnapshotId}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${s.SnapshotId}?`} />
            </>
          ),
        }))}
    />
  );
  return { body };
}
