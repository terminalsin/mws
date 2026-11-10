import { GetPermissionCommand, ListPermissionAssociationsCommand, ListPermissionVersionsCommand } from "@aws-sdk/client-ram";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { CreatePermissionVersion } from "@mws-dashboard/ui/model/ram";
import { Boxes, Check, GitBranch, Plus, RefreshCw, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, permissionHref, ram, shareHref } from "../../../lib/clients";
import { createPermissionVersion, deletePermission, deletePermissionVersion, replaceAssociations, setDefaultVersion } from "../actions";

export const metadata: Metadata = { title: "Managed permission" };

type Props = { searchParams: Promise<{ arn?: string; version?: string }> };

const pretty = (json: string | undefined) => {
  try {
    return JSON.stringify(JSON.parse(json ?? ""), null, 2);
  } catch {
    return json ?? "";
  }
};

export default async function Permission({ searchParams }: Props) {
  const { arn = "", version } = await searchParams;
  const back = { href: "/ram?tab=permissions", label: "Managed permissions" };
  const data = await load(async () => {
    const client = await ram();
    const [p, versions, shares] = await Promise.all([
      client.send(new GetPermissionCommand({ permissionArn: arn, permissionVersion: version ? Number(version) : undefined })).then((r) => r.permission!),
      all(
        (nextToken) => client.send(new ListPermissionVersionsCommand({ permissionArn: arn, nextToken })),
        (r) => r.permissions,
        (r) => r.nextToken,
      ).catch(() => []),
      all(
        (nextToken) => client.send(new ListPermissionAssociationsCommand({ permissionArn: arn, nextToken })),
        (r) => r.permissions,
        (r) => r.nextToken,
      ).catch(() => []),
    ]);
    return { p, versions, shares };
  });
  if (!data.ok) {
    return (
      <Page title="Managed permission" icon={ICONS.ram} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { p, versions, shares } = data.value;
  const customer = p.permissionType === "CUSTOMER_MANAGED";
  const current = versions.find((v) => v.defaultVersion)?.version ?? p.version;
  return (
    <Page
      title={p.name}
      icon={ICONS.ram}
      back={back}
      subtitle={arn}
      actions={
        customer ? (
          <>
            <Sheet title="Create version" label="Create version" icon={<Plus size={16} />} testId="create-permission-version">
              <ActionForm action={createPermissionVersion.bind(null, arn)} submit="Create version" testId="create-permission-version">
                <Field label="Policy template" rule={CreatePermissionVersion.policyTemplate} format="json" member="policyTemplate">
                  <textarea name="policy" rows={10} className="code-editor" defaultValue={pretty(p.permission)} />
                </Field>
              </ActionForm>
            </Sheet>
            <ActionForm action={deletePermission.bind(null, arn)} submit="Delete permission" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${p.name}?`} testId="delete-permission" />
          </>
        ) : undefined
      }
    >
      <Specs
        items={[
          { label: "Type", icon: <AwsIcon icon={ICONS.ram} size={16} />, value: customer ? "Customer managed" : "AWS managed" },
          { label: "Resource type", icon: <Boxes size={15} />, value: p.resourceType },
          { label: "Version", icon: <GitBranch size={15} />, value: `v${p.version}${p.defaultVersion ? " (default)" : ""}` },
          p.status && { label: "Status", icon: <AwsIcon icon={ICONS.ram} size={16} />, value: <Status tone={p.status === "ATTACHABLE" ? "good" : "warn"}>{p.status.toLowerCase()}</Status> },
          { label: "Updated", icon: <RefreshCw size={15} />, value: ago(p.lastUpdatedTime ?? p.creationTime) },
        ]}
      />
      <Section title={`Policy · v${p.version}`} plain>
        <CodeBlock value={pretty(p.permission)} label="Policy template" />
      </Section>
      <Section title="Versions" count={versions.length} plain>
        <List
          label="Versions"
          empty={<Empty icon={ICONS.ram} />}
          rows={versions
            .slice()
            .sort((a, b) => Number(b.version) - Number(a.version))
            .map((v) => ({
              key: v.version!,
              icon: <GitBranch size={16} />,
              title: `Version ${v.version}`,
              subtitle: ago(v.creationTime),
              href: permissionHref(arn, v.version),
              meta: (
                <>
                  {v.defaultVersion && <Pill tone="info">Default</Pill>}
                  {String(v.version) === (version ?? String(p.version)) && <Pill>Shown</Pill>}
                </>
              ),
              actions:
                customer && !v.defaultVersion ? (
                  <>
                    <ActionForm action={setDefaultVersion.bind(null, arn, Number(v.version))} submit={`Make version ${v.version} default`} icon={<Check size={15} />} />
                    <ActionForm action={replaceAssociations.bind(null, arn, Number(v.version))} submit={`Move shares on version ${v.version} to version ${current}`} icon={<RefreshCw size={15} />} />
                    <ActionForm action={deletePermissionVersion.bind(null, arn, Number(v.version))} submit={`Delete version ${v.version}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete version ${v.version}?`} />
                  </>
                ) : undefined,
            }))}
        />
      </Section>
      <Section title="Associated resource shares" count={shares.length} plain>
        <List
          label="Associated shares"
          empty={<Empty icon={ICONS.ram} />}
          rows={shares.map((s) => ({
            key: `${s.resourceShareArn}-${s.permissionVersion}`,
            icon: <AwsIcon icon={ICONS.ram} size={22} />,
            title: s.resourceShareArn?.split("/").pop(),
            subtitle: s.resourceType,
            href: shareHref(s.resourceShareArn),
            meta: (
              <>
                <span>v{s.permissionVersion}</span>
                {s.defaultVersion === false && <Status tone="warn">not default</Status>}
                {s.status && <Status tone={s.status === "ASSOCIATED" ? "good" : "warn"}>{s.status.toLowerCase()}</Status>}
              </>
            ),
          }))}
        />
      </Section>
    </Page>
  );
}
