import { DescribePackageCommand, GetAssociatedPackageGroupCommand, ListPackageVersionsCommand, type PackageFormat } from "@aws-sdk/client-codeartifact";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { ArrowUpFromLine, Boxes, Globe, ShieldCheck, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { codeartifact, FORMAT_ICONS } from "../../../lib/clients";
import { groupHref, packageTitle, repoHref, versionHref } from "../../../lib/refs";
import { STATUS_TONE, VersionActions } from "../../../lib/versions";
import { deletePackage, setOrigin } from "../actions";

export const metadata: Metadata = { title: "Package" };

type Props = { searchParams: Promise<{ domain?: string; owner?: string; repo?: string; format?: string; namespace?: string; package?: string }> };

const restriction = (v?: string) => <Status tone={v === "BLOCK" ? "warn" : "good"}>{v === "BLOCK" ? "blocked" : "allowed"}</Status>;

export default async function PackagePage({ searchParams }: Props) {
  const { domain = "", owner, repo = "", format = "npm", namespace, package: pkg = "" } = await searchParams;
  const ref = { domain, domainOwner: owner, repository: repo, format, namespace, package: pkg };
  const back = { href: repoHref(domain, repo, owner), label: repo };
  const title = packageTitle(format, namespace, pkg);
  const data = await load(async () => {
    const client = await codeartifact();
    const args = { domain, domainOwner: owner, repository: repo, format: format as PackageFormat, namespace, package: pkg };
    const [versions, description, group] = await Promise.all([
      all((nextToken) => client.send(new ListPackageVersionsCommand({ ...args, nextToken })), (r) => r.versions, (r) => r.nextToken),
      client.send(new DescribePackageCommand(args)).then((r) => r.package!),
      client
        .send(new GetAssociatedPackageGroupCommand({ domain, domainOwner: owner, format: format as PackageFormat, namespace, package: pkg }))
        .then((r) => r.packageGroup, () => undefined),
    ]);
    return { versions, description, group };
  });
  if (!data.ok) {
    return (
      <Page title={title} back={back} icon={FORMAT_ICONS[format]}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { versions, description, group } = data.value;
  const r = description.originConfiguration?.restrictions;
  return (
    <Page
      title={title}
      back={back}
      icon={FORMAT_ICONS[format]}
      actions={
        <>
          <Sheet title="Origin controls" label="Edit origin controls" icon={<ShieldCheck size={15} />} testId="origin-controls">
            <ActionForm action={setOrigin.bind(null, ref)} submit="Save" testId="origin-controls">
              <Field label="Publish" hint="New versions published directly to this repository">
                <select name="publish" defaultValue={r?.publish ?? "ALLOW"}>
                  <option value="ALLOW">Allow</option>
                  <option value="BLOCK">Block</option>
                </select>
              </Field>
              <Field label="Upstream" hint="New versions pulled from upstream and public repositories">
                <select name="upstream" defaultValue={r?.upstream ?? "ALLOW"}>
                  <option value="ALLOW">Allow</option>
                  <option value="BLOCK">Block</option>
                </select>
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm action={deletePackage.bind(null, ref)} submit="Delete package" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${title} and all its versions?`} />
        </>
      }
    >
      <Specs
        items={[
          { label: "Format", icon: <AwsIcon icon={FORMAT_ICONS[format] ?? FORMAT_ICONS.generic} size={15} />, value: format },
          { label: "Publish", icon: <Upload size={15} />, value: restriction(r?.publish) },
          { label: "Upstream", icon: <ArrowUpFromLine size={15} />, value: restriction(r?.upstream) },
          group?.pattern && {
            label: "Package group",
            icon: <Boxes size={15} />,
            value: <Link href={groupHref(group.domainName ?? domain, group.pattern, owner)}>{group.pattern}</Link>,
          },
        ]}
      />
      <Section title="Versions" count={versions.length} plain>
        <List
          label="Versions"
          empty={<Empty icon={FORMAT_ICONS[format]} />}
          rows={versions.map((v) => ({
            key: v.version!,
            icon: <AwsIcon icon={FORMAT_ICONS[format] ?? FORMAT_ICONS.generic} size={18} />,
            title: v.version,
            href: versionHref(ref, v.version!),
            meta: (
              <>
                {v.origin?.originType === "EXTERNAL" && (
                  <Pill icon={<Globe size={11} />}>{v.origin.domainEntryPoint?.externalConnectionName?.replace("public:", "") ?? "public"}</Pill>
                )}
                {v.origin?.originType === "INTERNAL" && v.origin.domainEntryPoint?.repositoryName && v.origin.domainEntryPoint.repositoryName !== repo && (
                  <Pill icon={<ArrowUpFromLine size={11} />}>{v.origin.domainEntryPoint.repositoryName}</Pill>
                )}
                <Status tone={STATUS_TONE[v.status ?? ""] ?? "neutral"}>{v.status?.toLowerCase()}</Status>
              </>
            ),
            actions: <VersionActions pkg={ref} version={v.version!} status={v.status} name={title} />,
          }))}
        />
      </Section>
    </Page>
  );
}

