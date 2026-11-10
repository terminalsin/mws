import { DescribeFileSystemsCommand } from "@aws-sdk/client-efs";
import { ago, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { CreateFileSystem as Rules } from "@mws-dashboard/ui/model/efs";
import { Lock } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, efs } from "../../lib/clients";
import { vpcs } from "../../lib/network";
import { createFileSystem } from "./actions";

export const metadata: Metadata = { title: "EFS" };

// The name is the file system's Name tag (optional, though a tag needs a value).
const NAME: Rule = { ...ruleAt(Rules, "Tags.Value"), required: false, hint: "Letters, digits, spaces and _ . : / = + - @" };

export default async function FileSystems() {
  const [list, networks] = await Promise.all([load(async () => (await (await efs()).send(new DescribeFileSystemsCommand({}))).FileSystems ?? []), load(vpcs)]);
  const create = (
    <Sheet title="Create file system" label="Create file system" testId="create-file-system">
      <ActionForm action={createFileSystem} submit="Create" testId="create-file-system">
        <Field label="Name" rule={NAME} member="Tags.Value">
          <input name="name" autoFocus />
        </Field>
        <Field label="VPC" member="SubnetId">
          <select name="vpc" defaultValue={networks.ok ? networks.value.find((v) => v.IsDefault)?.VpcId : ""}>
            <option value="">No mount targets</option>
            {networks.ok && networks.value.map((v) => <option key={v.VpcId} value={v.VpcId}>{v.Tags?.find((t) => t.Key === "Name")?.Value ?? v.VpcId}</option>)}
          </select>
        </Field>
        <div className="form-row">
          <Field label="Throughput" rule={Rules.ThroughputMode}>
            <select name="throughput" defaultValue="elastic">
              <option value="elastic">Elastic</option>
              <option value="bursting">Bursting</option>
            </select>
          </Field>
          <Field label="Performance" rule={Rules.PerformanceMode}>
            <select name="performance" defaultValue="generalPurpose">
              <option value="generalPurpose">General Purpose</option>
              <option value="maxIO">Max I/O</option>
            </select>
          </Field>
        </div>
        <label className="check">
          <input type="checkbox" name="encrypted" defaultChecked /> Encrypted
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
            href: `/efs/fs?id=${f.FileSystemId}`,
            meta: (
              <>
                {f.Encrypted && <Lock size={13} aria-label="Encrypted" />}
                <span>{bytes(f.SizeInBytes?.Value)}</span>
                <Pill>{f.NumberOfMountTargets} mount targets</Pill>
                <Status tone={STATUS_TONE(f.LifeCycleState)}>{f.LifeCycleState}</Status>
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
