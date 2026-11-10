import { DescribeLaunchTemplateVersionsCommand, type LaunchTemplateVersion } from "@aws-sdk/client-ec2";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Specs, Tags } from "@mws-dashboard/ui";
import { Clock, GitBranchPlus, Layers, Star, Trash2, User } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { launchChoices } from "../../../lib/choices";
import { ICONS, LINKS, ec2 } from "../../../lib/clients";
import { listInstances, listTemplates } from "../../../lib/ec2";
import { LaunchFields } from "../../../lib/launch-fields";
import { VERSION_DESCRIPTION } from "../../../lib/rules";
import { LaunchSheet } from "../../../lib/views/instances";
import { TagsSheet } from "../../../lib/widgets";
import { createVersion, deleteTemplate, deleteVersion, setDefaultVersion } from "../templates";

type Props = { searchParams: Promise<{ id?: string; v?: string }> };

export const metadata: Metadata = { title: "Launch template" };

/** A version's data as facts, with links to what it names. */
function VersionFacts({ version }: { version: LaunchTemplateVersion }) {
  const d = version.LaunchTemplateData ?? {};
  const nic = d.NetworkInterfaces?.[0];
  const groups = d.SecurityGroupIds ?? nic?.Groups ?? [];
  const subnet = nic?.SubnetId;
  const profile = d.IamInstanceProfile?.Name ?? d.IamInstanceProfile?.Arn?.split("/").pop();
  const root = d.BlockDeviceMappings?.[0];
  return (
    <Facts
      items={[
        d.ImageId && ["AMI", <Link key="a" href={LINKS.image(d.ImageId)}>{d.ImageId}</Link>],
        d.InstanceType && ["Instance type", d.InstanceType],
        d.KeyName && ["Key pair", d.KeyName],
        subnet && ["Subnet", <Link key="s" href={LINKS.subnet(subnet)}>{subnet}</Link>],
        nic?.AssociatePublicIpAddress !== undefined && ["Public IP", nic.AssociatePublicIpAddress ? "Assign" : "Don't assign"],
        groups.length > 0 && [
          "Security groups",
          <span key="g" className="chips">
            {groups.map((g) => (
              <Link key={g} href={LINKS.group(g)} className="chip">
                {g}
              </Link>
            ))}
          </span>,
        ],
        profile && ["IAM instance profile", <Link key="p" href={LINKS.instanceProfile(profile)}>{profile}</Link>],
        root && ["Volumes", d.BlockDeviceMappings!.map((b) => `${b.DeviceName} ${b.Ebs?.VolumeSize ?? ""} GiB ${b.Ebs?.VolumeType ?? ""}`.replace(/\s+/g, " ").trim()).join(", ")],
        d.Monitoring?.Enabled && ["Monitoring", "Detailed"],
        d.DisableApiTermination && ["Termination protection", "on"],
        d.MetadataOptions?.HttpTokens && ["IMDSv2", d.MetadataOptions.HttpTokens === "required" ? "Required" : "Optional"],
        d.InstanceMarketOptions?.MarketType && ["Purchasing", d.InstanceMarketOptions.MarketType],
        d.UserData && ["User data", <CodeBlock key="u" value={Buffer.from(d.UserData, "base64").toString("utf8")} label="User data" />],
      ]}
    />
  );
}

export default async function LaunchTemplatePage({ searchParams }: Props) {
  const { id = "", v } = await searchParams;
  const back = { href: "/ec2?tab=templates", label: "Launch templates" };
  const client = await ec2();
  const data = await load(async () => {
    const [template] = await listTemplates().then((ts) => ts.filter((t) => t.LaunchTemplateId === id));
    if (!template) throw new Error(`The specified launch template, with template ID ${id}, does not exist.`);
    const versions = await all(
      (NextToken) => client.send(new DescribeLaunchTemplateVersionsCommand({ LaunchTemplateId: id, NextToken })),
      (r) => r.LaunchTemplateVersions,
      (r) => r.NextToken,
    );
    return { template, versions: versions.sort((a, b) => (b.VersionNumber ?? 0) - (a.VersionNumber ?? 0)) };
  });
  if (!data.ok) {
    return (
      <Page title={id} icon={ICONS.template} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { template: t, versions } = data.value;
  const [choices, launched] = await Promise.all([launchChoices(), load(() => listInstances([{ Name: "tag:aws:ec2launchtemplate:id", Values: [id] }]))]);
  const shown = versions.find((x) => String(x.VersionNumber) === v) ?? versions.find((x) => x.DefaultVersion) ?? versions[0];
  const here = LINKS.template(id);
  const managed = !!t.Operator?.Managed;
  const instances = launched.ok ? launched.value.filter((i) => i.State?.Name !== "terminated") : [];
  return (
    <Page
      title={t.LaunchTemplateName}
      icon={ICONS.template}
      back={back}
      subtitle={id}
      actions={
        <>
          <LaunchSheet template={id} />
          {!managed && (
            <>
              <Sheet title="New version" label="Create template version" icon={<GitBranchPlus size={16} />} testId="create-template-version">
                <ActionForm action={createVersion.bind(null, id)} submit="Create version" testId="create-template-version">
                  <Field label="Source version" member="SourceVersion" hint="Blank fields keep its values">
                    <select name="source" defaultValue={String(shown?.VersionNumber ?? "")}>
                      <option value="">None</option>
                      {versions.map((x) => (
                        <option key={x.VersionNumber} value={String(x.VersionNumber)}>
                          {x.VersionNumber}
                          {x.VersionDescription ? ` · ${x.VersionDescription}` : ""}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Version description" rule={VERSION_DESCRIPTION} member="VersionDescription">
                    <input name="description" />
                  </Field>
                  <LaunchFields choices={choices} mode="version" />
                  <label className="check">
                    <input type="checkbox" name="makeDefault" /> Make it the default
                  </label>
                </ActionForm>
              </Sheet>
              <ActionForm action={deleteTemplate.bind(null, id, true)} submit="Delete template" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${t.LaunchTemplateName} and all its versions?`} testId="delete-template" />
            </>
          )}
        </>
      }
    >
      <Specs
        items={[
          { label: "Default version", icon: <Star size={15} />, value: `v${t.DefaultVersionNumber}` },
          { label: "Versions", icon: <Layers size={15} />, value: `${versions.length} (latest v${t.LatestVersionNumber})` },
          t.CreatedBy && { label: "Created by", icon: <User size={15} />, value: t.CreatedBy.split(/[:/]/).pop() },
          { label: "Created", icon: <Clock size={15} />, value: ago(t.CreateTime) },
          managed && { label: "Managed by", icon: <User size={15} />, value: <Pill>{t.Operator?.Principal}</Pill> },
        ]}
      />
      <Section title="Versions" count={versions.length} plain>
        <List
          label="Versions"
          rows={versions.map((x) => ({
            key: String(x.VersionNumber),
            icon: x.DefaultVersion ? <Star size={18} aria-label="Default" fill="currentColor" /> : <Layers size={18} aria-hidden />,
            title: `Version ${x.VersionNumber}`,
            subtitle: [x.VersionDescription, x.LaunchTemplateData?.ImageId, x.LaunchTemplateData?.InstanceType].filter(Boolean).join(" · "),
            href: `${here}&v=${x.VersionNumber}`,
            meta: (
              <>
                {x.DefaultVersion && <Pill tone="good">default</Pill>}
                <span>{ago(x.CreateTime)}</span>
              </>
            ),
            actions: !managed && !x.DefaultVersion && (
              <>
                <ActionForm action={setDefaultVersion.bind(null, id, x.VersionNumber!)} submit={`Make version ${x.VersionNumber} the default`} icon={<Star size={15} />} />
                <ActionForm action={deleteVersion.bind(null, id, x.VersionNumber!)} submit={`Delete version ${x.VersionNumber}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete version ${x.VersionNumber}?`} />
              </>
            ),
          }))}
        />
      </Section>
      {shown && (
        <Section title={`Version ${shown.VersionNumber}`}>
          <VersionFacts version={shown} />
        </Section>
      )}
      {instances.length > 0 && (
        <Section title="Instances" count={instances.length} plain>
          <List
            label="Instances from this template"
            rows={instances.map((i) => ({
              key: i.InstanceId!,
              icon: <AwsIcon icon={ICONS.instance} size={22} />,
              title: i.Tags?.find((x) => x.Key === "Name")?.Value ?? i.InstanceId,
              subtitle: [i.InstanceId, i.InstanceType, `v${i.Tags?.find((x) => x.Key === "aws:ec2launchtemplate:version")?.Value ?? "?"}`].join(" · "),
              href: LINKS.instance(i.InstanceId!),
              meta: <span>{i.State?.Name}</span>,
            }))}
          />
        </Section>
      )}
      {!managed && (
        <Section title="Tags" count={t.Tags?.length ?? 0} actions={<TagsSheet id={id} tags={t.Tags} />}>
          {t.Tags?.length ? <Tags tags={t.Tags} /> : <span className="muted">No tags</span>}
        </Section>
      )}
    </Page>
  );
}
