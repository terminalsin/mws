import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Segments, Sheet } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS } from "../../../lib/clients";
import { SsmNav } from "../../../lib/nav";
import { listDocuments } from "../../../lib/nodes";
import { createDocument } from "./actions";
import { DocumentFields } from "./fields";

export const metadata: Metadata = { title: "Documents" };

type Props = { searchParams: Promise<{ owner?: string; type?: string }> };

const OWNERS = [
  { id: "Self", label: "Owned by me" },
  { id: "Amazon", label: "Owned by Amazon" },
  { id: "Private", label: "Shared with me" },
];

const TYPES = ["Command", "Automation", "Session", "Policy", "ChangeCalendar", "Package", "Automation.ChangeTemplate"];

export default async function Documents({ searchParams }: Props) {
  const { owner = "Self", type } = await searchParams;
  const docs = await load(() =>
    listDocuments([{ Key: "Owner", Values: [owner] }, ...(type ? [{ Key: "DocumentType", Values: [type] }] : [])]),
  );
  const create = (
    <Sheet title="Create document" label="Create document" testId="create-document">
      <ActionForm action={createDocument} submit="Create" testId="create-document">
        <DocumentFields taken={docs.ok && owner === "Self" ? docs.value.map((d) => d.Name!) : []} />
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
