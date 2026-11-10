import { DescribeAvailabilityZonesCommand } from "@aws-sdk/client-ec2";
import { ago, bytes, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { ruleAt } from "@mws-dashboard/ui/validation";
import { CreateFileSystem as Rules } from "@mws-dashboard/ui/model/efs";
import { Lock, MapPin } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, STATUS_TONE, allFileSystems, ec2, fsHref } from "../../lib/clients";
import { nameOf, vpcs } from "../../lib/network";
import { CreateFileSystemFields } from "../../lib/create-fields";
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
        <CreateFileSystemFields
          nameRule={NAME}
          vpcs={networks.ok ? networks.value.map((v) => ({ id: v.VpcId!, label: `${nameOf(v.Tags) ?? v.VpcId}${v.IsDefault ? " (default)" : ""}` })) : []}
          defaultVpc={networks.ok ? networks.value.find((v) => v.IsDefault)?.VpcId : undefined}
          zones={zones.ok ? zones.value : []}
        />
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
