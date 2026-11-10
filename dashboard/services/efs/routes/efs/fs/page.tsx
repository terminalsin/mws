import { DescribeAccessPointsCommand, DescribeFileSystemsCommand, DescribeMountTargetsCommand } from "@aws-sdk/client-efs";
import { bytes, load, region } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Section, Sheet, Specs, Status, Tags, type Rule } from "@mws-dashboard/ui";
import { CreateAccessPoint as Rules } from "@mws-dashboard/ui/model/efs";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { Gauge, HardDrive, KeyRound, Lock, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, efs } from "../../../lib/clients";
import { createAccessPoint, deleteAccessPoint, deleteFileSystem } from "../actions";

export const metadata: Metadata = { title: "File system" };

const NAME: Rule = { ...ruleAt(Rules, "Tags.Value"), required: false, hint: "Letters, digits, spaces and _ . : / = + - @" };
const PATH: Rule = { ...ruleAt(Rules, "RootDirectory.Path"), format: "dir", hint: "An absolute path, up to 4 levels" };
const UID: Rule = { ...ruleAt(Rules, "PosixUser.Uid"), default: 1000 };

type Props = { searchParams: Promise<{ id?: string }> };

export default async function FileSystem({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/efs", label: "File systems" };
  const data = await load(async () => {
    const client = await efs();
    const [f, targets, points] = await Promise.all([
      client.send(new DescribeFileSystemsCommand({ FileSystemId: id })).then((r) => r.FileSystems![0]),
      client.send(new DescribeMountTargetsCommand({ FileSystemId: id })).then((r) => r.MountTargets ?? []),
      client.send(new DescribeAccessPointsCommand({ FileSystemId: id })).then((r) => r.AccessPoints ?? []),
    ]);
    return { f, targets, points };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.fileSystem} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { f, targets, points } = data.value;
  const dns = `${id}.efs.${await region()}.amazonaws.com`;
  return (
    <Page
      title={f.Name ?? id}
      icon={ICONS.fileSystem}
      back={back}
      subtitle={f.FileSystemArn}
      actions={
        <>
          <Sheet title="Create access point" label="Create access point" icon={<KeyRound size={16} />} testId="create-access-point">
            <ActionForm action={createAccessPoint.bind(null, id)} submit="Create" testId="create-access-point">
              <Field label="Name" rule={NAME} member="Tags.Value">
                <input name="name" autoFocus />
              </Field>
              <div className="form-row">
                <Field label="Root directory" rule={PATH} member="RootDirectory.Path">
                  <input name="path" required defaultValue="/app" />
                </Field>
                <Field label="POSIX user id" rule={UID} member="PosixUser.Uid">
                  <input name="uid" type="number" min={0} defaultValue={1000} />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteFileSystem.bind(null, id, targets.map((t) => t.MountTargetId!))} submit="Delete file system" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${f.Name ?? id} and its mount targets?`} testId="delete-file-system" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Size", icon: <HardDrive size={15} />, value: bytes(f.SizeInBytes?.Value) },
          { label: "State", icon: <AwsIcon icon={ICONS.efs} size={16} />, value: <Status tone={STATUS_TONE(f.LifeCycleState)}>{f.LifeCycleState}</Status> },
          { label: "Throughput", icon: <Gauge size={15} />, value: f.ThroughputMode },
          f.Encrypted && { label: "Encrypted", icon: <Lock size={15} />, value: "Encrypted" },
        ]}
      />
      <Section title="Mount">
        <CodeBlock value={`sudo mount -t efs -o tls ${id}:/ /mnt/efs\n# or NFS\nsudo mount -t nfs4 -o nfsvers=4.1 ${dns}:/ /mnt/efs`} label="Mount commands" />
      </Section>
      <Section title="Mount targets" count={targets.length} plain>
        <List
          label="Mount targets"
          empty={<Empty icon={ICONS.efs} />}
          rows={targets.map((t) => ({
            key: t.MountTargetId!,
            icon: <AwsIcon icon="resource/AmazonVPCElasticNetworkInterface" size={22} />,
            title: t.IpAddress,
            subtitle: `${t.AvailabilityZoneName} · ${t.SubnetId}`,
            meta: <Status tone={STATUS_TONE(t.LifeCycleState)}>{t.LifeCycleState}</Status>,
          }))}
        />
      </Section>
      {points.length > 0 && (
        <Section title="Access points" count={points.length} plain>
          <List
            label="Access points"
            rows={points.map((p) => ({
              key: p.AccessPointId!,
              icon: <KeyRound size={18} />,
              title: p.Name ?? p.AccessPointId,
              subtitle: `${p.RootDirectory?.Path ?? "/"} · uid ${p.PosixUser?.Uid ?? "—"}`,
              meta: <Status tone={STATUS_TONE(p.LifeCycleState)}>{p.LifeCycleState}</Status>,
              actions: <ActionForm action={deleteAccessPoint.bind(null, p.AccessPointId!)} submit={`Delete ${p.AccessPointId}`} icon={<Trash2 size={15} />} tone="danger" confirm="Delete this access point?" />,
            }))}
          />
        </Section>
      )}
      <Tags tags={f.Tags} />
    </Page>
  );
}
