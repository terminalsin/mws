import { DescribeImageAttributeCommand, DescribeImagesCommand } from "@aws-sdk/client-ec2";
import { ago, load, region, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { Ban, CalendarClock, CircleCheck, Clock, Copy, Cpu, Globe, HardDrive, Pencil, Power, Share2, ShieldCheck, ShieldOff, Trash2, X } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, LINKS, ec2, nameTag } from "../../../lib/clients";
import { RESOURCE_TONE, listInstances } from "../../../lib/ec2";
import { ACCOUNT_ID, COPY_NAME, IMAGE_DESCRIPTION } from "../../../lib/rules";
import { osIcon } from "../../../lib/views/images";
import { LaunchSheet } from "../../../lib/views/instances";
import { regions } from "../../../lib/views/snapshots";
import { TagsSheet } from "../../../lib/widgets";
import { copyImage, deprecateImage, deregisterImage, enableImage, protectImage, setDescription, shareImage, undeprecateImage, unshareImage } from "../images";

type Props = { searchParams: Promise<{ id?: string }> };

export const metadata: Metadata = { title: "AMI" };

export default async function ImagePage({ searchParams }: Props) {
  const { id = "" } = await searchParams;
  const back = { href: "/ec2?tab=images", label: "AMIs" };
  const client = await ec2();
  const image = await load(async () => {
    const i = (await client.send(new DescribeImagesCommand({ ImageIds: [id], IncludeDeprecated: true, IncludeDisabled: true }))).Images?.[0];
    if (!i) throw new Error(`The image id '[${id}]' does not exist`);
    return i;
  });
  if (!image.ok) {
    return (
      <Page title={id} icon={ICONS.ami} back={back}>
        <ErrorNotice error={image.error} />
      </Page>
    );
  }
  const i = image.value;
  const [permissions, regionList, here, users, mine] = await Promise.all([
    load(async () => (await client.send(new DescribeImageAttributeCommand({ ImageId: id, Attribute: "launchPermission" }))).LaunchPermissions ?? []),
    load(regions),
    region(),
    load(() => listInstances([{ Name: "image-id", Values: [id] }])),
    load(async () => ((await client.send(new DescribeImagesCommand({ ImageIds: [id], Owners: ["self"], IncludeDeprecated: true, IncludeDisabled: true }))).Images ?? []).length > 0),
  ]);
  // Only the owner can change an image; Amazon's are read-only here.
  const own = mine.ok && mine.value;
  const deprecated = i.DeprecationTime && new Date(i.DeprecationTime).getTime() <= Date.now();
  const protectedImage = i.DeregistrationProtection?.startsWith("enabled");
  const disabled = i.State === "disabled";
  const running = users.ok ? users.value.filter((x) => x.State?.Name !== "terminated") : [];
  const title = i.Name ?? id;
  return (
    <Page
      title={title}
      icon={osIcon(`${i.PlatformDetails} ${i.Name}`)}
      back={back}
      subtitle={id}
      actions={
        <>
          {i.State === "available" && <LaunchSheet image={id} />}
          <Sheet title={`Copy ${title}`} label="Copy AMI" icon={<Copy size={16} />} testId="copy-image">
            <ActionForm action={copyImage.bind(null, id)} submit="Copy" testId="copy-image">
              <Field label="Name" rule={COPY_NAME} member="Name">
                <input name="name" required defaultValue={`${i.Name ?? id}-copy`.slice(0, 128)} autoFocus />
              </Field>
              <Field label="Description" rule={IMAGE_DESCRIPTION} member="Description">
                <input name="description" defaultValue={`Copy of ${id}`} />
              </Field>
              <Field label="Destination Region" member="DestinationRegion">
                <select name="region" defaultValue={here}>
                  {(regionList.ok ? regionList.value : [here]).map((r) => (
                    <option key={r}>{r}</option>
                  ))}
                </select>
              </Field>
              <label className="check">
                <input type="checkbox" name="encrypted" /> Encrypt snapshots
              </label>
              {own && (
                <label className="check">
                  <input type="checkbox" name="copyTags" defaultChecked /> Copy tags
                </label>
              )}
            </ActionForm>
          </Sheet>
          {own && (
            <>
              <Sheet title="Description" label="Edit description" icon={<Pencil size={16} />} testId="image-description">
                <ActionForm action={setDescription.bind(null, id)} submit="Save" testId="image-description">
                  <Field label="Description" rule={IMAGE_DESCRIPTION} member="Description">
                    <input name="description" defaultValue={i.Description} autoFocus />
                  </Field>
                </ActionForm>
              </Sheet>
              <ActionForm
                action={protectImage.bind(null, id, !protectedImage)}
                submit={protectedImage ? "Turn off deregistration protection" : "Turn on deregistration protection"}
                icon={protectedImage ? <ShieldOff size={16} /> : <ShieldCheck size={16} />}
                testId="protect-image"
              />
              <ActionForm action={enableImage.bind(null, id, disabled)} submit={disabled ? "Enable AMI" : "Disable AMI"} icon={disabled ? <CircleCheck size={16} /> : <Ban size={16} />} confirm={disabled ? undefined : `Disable ${id}? Nobody can launch it until it is enabled.`} />
              {!protectedImage && (
                <ActionForm
                  action={deregisterImage.bind(null, id, true)}
                  submit="Deregister"
                  icon={<Trash2 size={16} />}
                  tone="danger"
                  confirm={`Deregister ${id} and delete its snapshots?`}
                  testId="deregister-image"
                />
              )}
            </>
          )}
        </>
      }
    >
      <Specs
        items={[
          { label: "State", icon: <Power size={15} />, value: <Status tone={RESOURCE_TONE[i.State ?? ""] ?? "neutral"}>{i.State ?? ""}</Status> },
          deprecated && { label: "Deprecated", icon: <CalendarClock size={15} />, value: <Pill tone="warn">deprecated {ago(i.DeprecationTime)}</Pill> },
          { label: "Architecture", icon: <Cpu size={15} />, value: i.Architecture },
          i.Public && { label: "Visibility", icon: <Globe size={15} color="var(--warn)" />, value: <Pill tone="warn">public</Pill> },
          protectedImage && { label: "Deregistration protection", icon: <ShieldCheck size={15} />, value: "protected" },
          { label: "Created", icon: <Clock size={15} />, value: ago(i.CreationDate) },
        ]}
      />
      {i.StateReason?.Message && <ErrorNotice error={i.StateReason.Message} />}
      <Section>
        <Facts
          items={[
            i.Description && ["Description", i.Description],
            ["Platform", i.PlatformDetails],
            ["Owner", i.ImageOwnerAlias ?? i.OwnerId],
            i.SourceInstanceId && ["Source instance", <Link key="s" href={LINKS.instance(i.SourceInstanceId)}>{i.SourceInstanceId}</Link>],
            ["Root device", `${i.RootDeviceName} (${i.RootDeviceType})`],
            ["Virtualization", i.VirtualizationType],
            i.BootMode && ["Boot mode", i.BootMode],
            i.ImdsSupport && ["IMDS", i.ImdsSupport === "v2.0" ? "IMDSv2 required" : i.ImdsSupport],
            i.DeprecationTime && !deprecated && ["Deprecates", when(i.DeprecationTime)],
            i.ImageLocation && ["Location", <code key="l">{i.ImageLocation}</code>],
          ]}
        />
      </Section>
      <Section title="Block devices" count={i.BlockDeviceMappings?.length ?? 0} plain>
        <List
          label="Block devices"
          rows={(i.BlockDeviceMappings ?? []).map((b) => ({
            key: b.DeviceName!,
            icon: b.Ebs ? <AwsIcon icon={ICONS.snapshot} size={22} /> : <HardDrive size={18} aria-hidden />,
            title: b.DeviceName,
            subtitle: b.Ebs?.SnapshotId ?? b.VirtualName,
            href: b.Ebs?.SnapshotId && own ? "/ec2?tab=snapshots" : undefined,
            meta: b.Ebs && (
              <>
                {b.Ebs.Encrypted && <Pill tone="info">encrypted</Pill>}
                <span>
                  {b.Ebs.VolumeSize} GiB {b.Ebs.VolumeType}
                </span>
              </>
            ),
          }))}
        />
      </Section>
      {own && (
        <Section
          title="Permissions"
          icon={<Share2 size={16} aria-hidden />}
          plain
          actions={
            <Sheet title="Share AMI" label="Share AMI" icon={<Share2 size={15} />} testId="share-image">
              <ActionForm action={shareImage.bind(null, id)} submit="Share" testId="share-image">
                <Field label="Account ID" rule={{ ...ACCOUNT_ID, aliases: { public: "all", everyone: "all" }, pattern: "^(\\d{12}|all)$", hint: "A 12-digit account ID, or all (public)" }} member="UserId">
                  <input name="account" required autoFocus />
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          {permissions.ok ? (
            <List
              label="Launch permissions"
              empty={<span className="muted">Private</span>}
              rows={permissions.value.map((p) => {
                const who = p.Group === "all" ? "all" : (p.UserId ?? p.OrganizationArn ?? p.OrganizationalUnitArn ?? "");
                return {
                  key: who,
                  icon: p.Group === "all" ? <Globe size={18} color="var(--warn)" aria-hidden /> : <AwsIcon icon="group/AWSAccount" size={20} />,
                  title: p.Group === "all" ? "Public" : who,
                  actions: <ActionForm action={unshareImage.bind(null, id, who)} submit={`Stop sharing with ${who}`} icon={<X size={15} />} />,
                };
              })}
            />
          ) : (
            <ErrorNotice error={permissions.error} />
          )}
        </Section>
      )}
      {own && (
        <Section title="Deprecation" icon={<CalendarClock size={16} aria-hidden />}>
          {i.DeprecationTime ? (
            <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
              {when(i.DeprecationTime)}
              <ActionForm action={undeprecateImage.bind(null, id)} submit="Cancel deprecation" icon={<X size={15} />} />
            </span>
          ) : (
            <ActionForm action={deprecateImage.bind(null, id)} submit="Schedule" testId="deprecate-image" inline>
              <Field label="Deprecate at (UTC)" member="DeprecateAt">
                <input name="at" type="datetime-local" required />
              </Field>
            </ActionForm>
          )}
        </Section>
      )}
      {running.length > 0 && (
        <Section title="Instances" count={running.length} plain>
          <List
            label="Instances from this AMI"
            rows={running.map((x) => ({
              key: x.InstanceId!,
              icon: <AwsIcon icon={ICONS.instance} size={22} />,
              title: nameTag(x) ?? x.InstanceId,
              subtitle: x.InstanceType,
              href: LINKS.instance(x.InstanceId!),
              meta: <Status tone="neutral">{x.State?.Name ?? ""}</Status>,
            }))}
          />
        </Section>
      )}
      {own && (
        <Section title="Tags" count={i.Tags?.length ?? 0} actions={<TagsSheet id={id} tags={i.Tags} />}>
          {i.Tags?.length ? <Tags tags={i.Tags} /> : <span className="muted">No tags</span>}
        </Section>
      )}
    </Page>
  );
}
