import { DescribeAvailabilityZonesCommand } from "@aws-sdk/client-ec2";
import { ago, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { CreateFileSystem as Rules } from "@mws-dashboard/ui/model/efs";
import { Lock, MapPin } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, allFileSystems, ec2, fsHref } from "../../lib/clients";
import { nameOf, vpcs } from "../../lib/network";
import { IA_OPTIONS } from "../../lib/options";
import { createFileSystem } from "./actions";

export const metadata: Metadata = { title: "EFS" };

// The name is the file system's Name tag (optional, though a tag needs a value).
const NAME: Rule = { ...ruleAt(Rules, "Tags.Value"), required: false, hint: "Letters, digits, spaces and _ . : / = + - @" };

export default async function FileSystems() {
  const [list, networks, zones] = await Promise.all([
    load(allFileSystems),
    load(vpcs),
    load(async () => ((await (await ec2()).send(new DescribeAvailabilityZonesCommand({}))).AvailabilityZones ?? []).map((z) => z.ZoneName!)),
  ]);
  const create = (
    <Sheet title="Create file system" label="Create file system" testId="create-file-system">
      <ActionForm action={createFileSystem} submit="Create" testId="create-file-system">
        <Field label="Name" rule={NAME} member="Tags.Value">
          <input name="name" autoFocus />
        </Field>
        <Field label="VPC" member="SubnetId" hint="A mount target in each Availability Zone">
          <select name="vpc" defaultValue={networks.ok ? networks.value.find((v) => v.IsDefault)?.VpcId : ""}>
            <option value="">No mount targets</option>
            {networks.ok && networks.value.map((v) => <option key={v.VpcId} value={v.VpcId}>{nameOf(v.Tags) ?? v.VpcId}</option>)}
          </select>
        </Field>
        <div className="form-row">
          <Field label="Storage" rule={Rules.AvailabilityZoneName} member="AvailabilityZoneName">
            <select name="az" defaultValue="">
              <option value="">Regional</option>
              {(zones.ok ? zones.value : []).map((z) => (
                <option key={z} value={z}>
                  One Zone: {z}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Performance" rule={Rules.PerformanceMode}>
            <select name="performance" defaultValue="generalPurpose">
              <option value="generalPurpose">General Purpose</option>
              <option value="maxIO">Max I/O</option>
            </select>
          </Field>
        </div>
        <div className="form-row">
          <Field label="Throughput" rule={Rules.ThroughputMode}>
            <select name="throughput" defaultValue="elastic">
              <option value="elastic">Elastic</option>
              <option value="bursting">Bursting</option>
              <option value="provisioned">Provisioned</option>
            </select>
          </Field>
          <Field label="Provisioned MiB/s" rule={Rules.ProvisionedThroughputInMibps} hint="Provisioned only">
            <input name="mibps" type="number" min={1} step="any" />
          </Field>
        </div>
        <div className="form-row">
          <Field label="Transition to Infrequent Access" member="LifecyclePolicies">
            <select name="ia" defaultValue="AFTER_30_DAYS">
              <option value="">None</option>
              {IA_OPTIONS.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
          </Field>
          <Field label="KMS key" rule={Rules.KmsKeyId} hint="Empty uses aws/elasticfilesystem">
            <input name="kms" />
          </Field>
        </div>
        <label className="check">
          <input type="checkbox" name="encrypted" defaultChecked /> Encrypted
        </label>
        <label className="check">
          <input type="checkbox" name="backup" defaultChecked /> Automatic backups
        </label>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="File systems" actions={create}>
      {list.ok ? (
        <List
          label="File systems"
          empty={<Empty icon={ICONS.efs} action={create} />}
          rows={list.value.map((f) => ({
            key: f.FileSystemId!,
            icon: <AwsIcon icon={ICONS.fileSystem} size={24} />,
            title: f.Name ?? f.FileSystemId,
            subtitle: f.Name ? f.FileSystemId : undefined,
            href: fsHref(f.FileSystemId!),
            meta: (
              <>
                {f.Encrypted && <Lock size={13} aria-label="Encrypted" />}
                {f.AvailabilityZoneName && (
                  <Pill icon={<MapPin size={12} aria-hidden />} title="One Zone">
                    {f.AvailabilityZoneName}
                  </Pill>
                )}
                <span>{bytes(f.SizeInBytes?.Value)}</span>
                <Pill>{f.NumberOfMountTargets} mount targets</Pill>
                <Status tone={STATUS_TONE(f.LifeCycleState)}>{f.LifeCycleState ?? ""}</Status>
                <span>{ago(f.CreationTime)}</span>
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
