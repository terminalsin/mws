import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Segments, Sheet } from "@mws-dashboard/ui";
import { CreateDocument } from "@mws-dashboard/ui/model/ssm";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS } from "../../../lib/clients";
import { SsmNav } from "../../../lib/nav";
import { listDocuments } from "../../../lib/nodes";
import { createDocument } from "./actions";

export const metadata: Metadata = { title: "Documents" };

type Props = { searchParams: Promise<{ owner?: string; type?: string }> };

const OWNERS = [
  { id: "Self", label: "Owned by me" },
  { id: "Amazon", label: "Owned by Amazon" },
  { id: "Private", label: "Shared with me" },
];

const TYPES = ["Command", "Automation", "Session", "Policy", "ChangeCalendar", "Package", "Automation.ChangeTemplate"];

const SAMPLE = `schemaVersion: "2.2"
description: Say hello
parameters:
  name:
    type: String
    default: world
mainSteps:
  - action: aws:runShellScript
    name: hello
    inputs:
      runCommand:
        - echo "hello {{ name }}"
`;

export default async function Documents({ searchParams }: Props) {
  const { owner = "Self", type } = await searchParams;
  const docs = await load(() =>
    listDocuments([{ Key: "Owner", Values: [owner] }, ...(type ? [{ Key: "DocumentType", Values: [type] }] : [])]),
  );
  const create = (
    <Sheet title="Create document" label="Create document" testId="create-document">
      <ActionForm action={createDocument} submit="Create" testId="create-document">
        <Field label="Name" rule={CreateDocument.Name} unique taken={docs.ok && owner === "Self" ? docs.value.map((d) => d.Name!) : []} generate="name">
          <input name="name" required autoFocus placeholder="Hello-World" />
        </Field>
        <div className="form-row">
          <Field label="Type" rule={CreateDocument.DocumentType}>
            <select name="type" defaultValue="Command">
              {TYPES.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </Field>
          <Field label="Format" rule={CreateDocument.DocumentFormat}>
            <select name="format" defaultValue="YAML">
              <option>YAML</option>
              <option>JSON</option>
              <option>TEXT</option>
            </select>
          </Field>
        </div>
        <Field label="Content" rule={{ ...CreateDocument.Content, format: "yaml" }}>
          <textarea name="content" rows={14} className="code-editor" spellCheck={false} defaultValue={SAMPLE} required />
        </Field>
        <div className="form-row">
          <Field label="Target type" rule={CreateDocument.TargetType}>
            <input name="targetType" placeholder="/AWS::EC2::Instance" />
          </Field>
          <Field label="Version name" rule={CreateDocument.VersionName}>
            <input name="versionName" />
          </Field>
        </div>
        <Field label="Tags" format="tags">
          <textarea name="tags" rows={2} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  const q = (o: string, t?: string) => `/ssm/documents?owner=${o}${t ? `&type=${encodeURIComponent(t)}` : ""}`;
  return (
    <Page title="Documents" icon={ICONS.ssm} actions={create}>
      <SsmNav active="documents" />
      <Segments label="Owner" items={OWNERS.map((o) => ({ label: o.label, href: q(o.id, type), active: o.id === owner }))} />
      <nav className="chips" aria-label="Document type">
        <Link href={q(owner)} className={!type ? "tag active" : "tag"}>
          <span>All types</span>
        </Link>
        {TYPES.map((t) => (
          <Link key={t} href={q(owner, t)} className={type === t ? "tag active" : "tag"}>
            <span>{t}</span>
          </Link>
        ))}
      </nav>
      {docs.ok ? (
        <List
          label="Documents"
          empty={<Empty icon={ICONS.document} action={owner === "Self" ? create : undefined} />}
          rows={docs.value.map((d) => ({
            key: d.Name!,
            icon: <AwsIcon icon={d.DocumentType === "ChangeCalendar" ? ICONS.calendar : ICONS.document} size={24} />,
            title: d.DisplayName || d.Name,
            subtitle: [d.DisplayName ? d.Name : null, d.PlatformTypes?.join(", "), d.TargetType].filter(Boolean).join(" · "),
            href: `/ssm/document?name=${encodeURIComponent(d.Name!)}`,
            meta: (
              <>
                <Pill>{d.DocumentType}</Pill>
                {d.ReviewStatus && d.ReviewStatus !== "APPROVED" && <Pill tone="warn">{d.ReviewStatus.toLowerCase()}</Pill>}
                <span>v{d.DocumentVersion}</span>
                {d.CreatedDate && <span>{ago(d.CreatedDate)}</span>}
              </>
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={docs.error} />
      )}
    </Page>
  );
}
