import { DescribeDocumentCommand, DescribeDocumentPermissionCommand, GetDocumentCommand, ListDocumentVersionsCommand, ListTagsForResourceCommand } from "@aws-sdk/client-ssm";
import { ago, all, load, when } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Status, Table, Tags } from "@mws-dashboard/ui";
import { ModifyDocumentPermission, UpdateDocument } from "@mws-dashboard/ui/model/ssm";
import { BadgeCheck, FilePlus2, Play, Share2, Tag, Terminal, Trash2, X } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../lib/clients";
import { tone, words } from "../../../lib/status";
import { saveTags } from "../actions";
import { deleteDocument, setDefaultVersion, share, unshare, updateDocument } from "../documents/actions";

export const metadata: Metadata = { title: "Document" };

type Props = { searchParams: Promise<{ name?: string; tab?: string; version?: string }> };

const ACCOUNTS = { ...ModifyDocumentPermission.AccountIdsToAdd, item: { type: "string" as const, format: "principal" as const, pattern: "^(\\d{12}|All)$" } };

export default async function Document({ searchParams }: Props) {
  const { name = "", tab = "content", version } = await searchParams;
  const back = { href: "/ssm/documents", label: "Documents" };
  const data = await load(async () => {
    const c = await ssm();
    const [doc, content] = await Promise.all([
      c.send(new DescribeDocumentCommand({ Name: name, DocumentVersion: version })).then((r) => r.Document!),
      c.send(new GetDocumentCommand({ Name: name, DocumentVersion: version })),
    ]);
    return { doc, content };
  });
  if (!data.ok) {
    return (
      <Page title={name || "Document"} icon={ICONS.document} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { doc, content } = data.value;
  const c = await ssm();
  const own = doc.Owner !== "Amazon" && !name.startsWith("arn:");
  const base = `/ssm/document?name=${encodeURIComponent(name)}`;
  const tabs = [
    { id: "content", label: "Content" },
    { id: "parameters", label: "Parameters", count: doc.Parameters?.length || undefined },
    { id: "versions", label: "Versions", count: Number(doc.LatestVersion) || undefined },
    own && { id: "permissions", label: "Permissions" },
    own && { id: "tags", label: "Tags", count: doc.Tags?.length || undefined },
  ].filter((t): t is { id: string; label: string; count?: number } => !!t);
  const active = tabs.some((t) => t.id === tab) ? tab : "content";
  const runHref = doc.DocumentType === "Command" ? `/ssm/commands/send?document=${encodeURIComponent(name)}` : doc.DocumentType === "Automation" ? `/ssm/automation/start?document=${encodeURIComponent(name)}` : undefined;

  let body: React.ReactNode = null;
  if (active === "content") {
    body = (
      <Section title={`Version ${content.DocumentVersion}${content.VersionName ? ` (${content.VersionName})` : ""}`}>
        <CodeBlock value={content.Content} label="Document content" />
      </Section>
    );
  } else if (active === "parameters") {
    body = (
      <Table
        label="Parameters"
        rowKey={(p) => p.Name!}
        rows={doc.Parameters ?? []}
        empty={<Empty>No parameters</Empty>}
        columns={[
          { header: "Name", cell: (p) => <code>{p.Name}</code> },
          { header: "Type", cell: (p) => p.Type },
          { header: "Default", cell: (p) => (p.DefaultValue ? <code className="clip">{p.DefaultValue}</code> : null) },
          { header: "Description", cell: (p) => p.Description },
        ]}
      />
    );
  } else if (active === "versions") {
    const versions = await load(() => all((NextToken) => c.send(new ListDocumentVersionsCommand({ Name: name, NextToken })), (r) => r.DocumentVersions, (r) => r.NextToken));
    body = versions.ok ? (
      <List
        label="Versions"
        rows={[...versions.value]
          .sort((a, b) => Number(b.DocumentVersion) - Number(a.DocumentVersion))
          .map((v) => ({
            key: v.DocumentVersion!,
            icon: <span className="pill">v{v.DocumentVersion}</span>,
            title: v.VersionName || `Version ${v.DocumentVersion}`,
            subtitle: [v.DocumentFormat, v.CreatedDate ? ago(v.CreatedDate) : null, v.StatusInformation].filter(Boolean).join(" · "),
            href: `${base}&version=${v.DocumentVersion}`,
            meta: (
              <>
                {v.IsDefaultVersion && <Pill tone="good">default</Pill>}
                {v.ReviewStatus && <Pill>{v.ReviewStatus.toLowerCase()}</Pill>}
                {v.Status && v.Status !== "Active" && <Status tone={tone(v.Status)}>{v.Status}</Status>}
              </>
            ),
            actions: own && !v.IsDefaultVersion && (
              <>
                <ActionForm action={setDefaultVersion.bind(null, name, v.DocumentVersion!)} submit={`Make version ${v.DocumentVersion} the default`} icon={<BadgeCheck size={15} />} />
                <ActionForm action={deleteDocument.bind(null, name, v.DocumentVersion!)} submit={`Delete version ${v.DocumentVersion}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete version ${v.DocumentVersion}?`} />
              </>
            ),
          }))}
      />
    ) : (
      <ErrorNotice error={versions.error} />
    );
  } else if (active === "permissions") {
    const perm = await load(() => c.send(new DescribeDocumentPermissionCommand({ Name: name, PermissionType: "Share" })));
    body = (
      <Section
        title="Shared with"
        plain
        actions={
          <Sheet title="Share document" label="Share with accounts" icon={<Share2 size={16} />} testId="share-document">
            <ActionForm action={share.bind(null, name)} submit="Share" testId="share-document">
              <Field label="Account IDs" rule={ACCOUNTS} member="AccountIdsToAdd" hint="12-digit IDs, or All for public">
                <input name="accounts" required placeholder="111122223333" />
              </Field>
              <Field label="Version" rule={ModifyDocumentPermission.SharedDocumentVersion}>
                <select name="version" defaultValue="$DEFAULT">
                  <option>$DEFAULT</option>
                  <option>$LATEST</option>
                  <option>$ALL</option>
                </select>
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {perm.ok ? (
          <List
            label="Accounts"
            empty={<Empty>Not shared</Empty>}
            rows={(perm.value.AccountSharingInfoList ?? perm.value.AccountIds?.map((AccountId) => ({ AccountId, SharedDocumentVersion: undefined })) ?? []).map((a) => ({
              key: a.AccountId!,
              title: a.AccountId === "all" || a.AccountId === "All" ? "Public" : a.AccountId,
              meta: a.SharedDocumentVersion ? <Pill>{a.SharedDocumentVersion}</Pill> : undefined,
              actions: <ActionForm action={unshare.bind(null, name, a.AccountId!)} submit={`Stop sharing with ${a.AccountId}`} icon={<X size={15} />} tone="danger" />,
            }))}
          />
        ) : (
          <ErrorNotice error={perm.error} />
        )}
      </Section>
    );
  } else if (active === "tags") {
    const tags = await c.send(new ListTagsForResourceCommand({ ResourceType: "Document", ResourceId: name })).then((r) => r.TagList ?? [], () => doc.Tags ?? []);
    body = (
      <Section
        title="Tags"
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, "Document", name, tags.map((t) => t.Key!), "/ssm/document")} submit="Save" testId="edit-tags">
              <Field label="Tags" format="tags">
                <textarea name="tags" rows={6} defaultValue={tags.map((t) => `${t.Key}=${t.Value ?? ""}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {tags.length ? <Tags tags={tags} /> : <Empty>No tags</Empty>}
      </Section>
    );
  }

  return (
    <Page
      title={doc.DisplayName || doc.Name}
      icon={doc.DocumentType === "ChangeCalendar" ? ICONS.calendar : ICONS.document}
      back={back}
      subtitle={doc.Name}
      actions={
        <>
          {runHref && (
            <Link className="icon-button primary" href={runHref} aria-label={doc.DocumentType === "Command" ? "Run command" : "Execute automation"} title={doc.DocumentType === "Command" ? "Run command" : "Execute automation"}>
              {doc.DocumentType === "Command" ? <Terminal size={16} /> : <Play size={16} />}
            </Link>
          )}
          {own && (
            <Sheet title="New version" label="Create new version" icon={<FilePlus2 size={16} />} testId="update-document">
              <ActionForm action={updateDocument.bind(null, name)} submit="Create version" testId="update-document">
                <Field label="Format" rule={UpdateDocument.DocumentFormat}>
                  <select name="format" defaultValue={content.DocumentFormat ?? "YAML"}>
                    <option>YAML</option>
                    <option>JSON</option>
                    <option>TEXT</option>
                  </select>
                </Field>
                <Field label="Content" rule={{ ...UpdateDocument.Content, format: content.DocumentFormat === "JSON" ? "json" : "yaml" }}>
                  <textarea name="content" rows={16} className="code-editor" spellCheck={false} defaultValue={content.Content} required />
                </Field>
                <Field label="Version name" rule={UpdateDocument.VersionName}>
                  <input name="versionName" />
                </Field>
                <label className="check">
                  <input type="checkbox" name="makeDefault" defaultChecked /> Make it the default version
                </label>
              </ActionForm>
            </Sheet>
          )}
          {own && <ActionForm action={deleteDocument.bind(null, name, undefined)} submit="Delete document" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name} and all its versions?`} testId="delete-document" />}
        </>
      }
    >
      <Facts
        items={[
          ["Type", doc.DocumentType],
          ["Owner", doc.Owner],
          ["Default version", doc.DefaultVersion],
          ["Latest version", doc.LatestVersion],
          doc.Status && doc.Status !== "Active" && ["Status", <Status key="s" tone={tone(doc.Status)}>{words(doc.Status)}</Status>],
          doc.StatusInformation && ["Status information", doc.StatusInformation],
          doc.PlatformTypes?.length && ["Platforms", doc.PlatformTypes.join(", ")],
          doc.SchemaVersion && ["Schema", doc.SchemaVersion],
          doc.TargetType && ["Target type", doc.TargetType],
          doc.Description && ["Description", doc.Description],
          doc.CreatedDate && ["Created", when(doc.CreatedDate)],
          doc.ReviewStatus && ["Review", doc.ReviewStatus.toLowerCase()],
        ]}
      />
      <Segments label="Document" items={tabs.map((t) => ({ label: t.label, href: t.id === "content" ? base : `${base}&tab=${t.id}`, active: t.id === active, count: t.count }))} />
      {body}
    </Page>
  );
}
