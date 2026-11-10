import { DescribeDocumentCommand } from "@aws-sdk/client-ssm";
import { load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, Page, Section } from "@mws-dashboard/ui";
import { StartAutomationExecution } from "@mws-dashboard/ui/model/ssm";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../../lib/clients";
import { listDocuments } from "../../../../lib/nodes";
import { startAutomation } from "../actions";

export const metadata: Metadata = { title: "Execute automation" };

type Props = { searchParams: Promise<{ document?: string }> };

/** AWS's "Execute automation runbook": choose a runbook, fill its parameters. */
export default async function Start({ searchParams }: Props) {
  const { document } = await searchParams;
  const back = { href: "/ssm/automation", label: "Automation" };
  const [docs, doc] = await Promise.all([
    load(() => listDocuments([{ Key: "DocumentType", Values: ["Automation"] }])),
    document ? load(async () => (await (await ssm()).send(new DescribeDocumentCommand({ Name: document }))).Document!) : null,
  ]);
  const params = doc?.ok ? (doc.value.Parameters ?? []) : [];
  const lists = params.filter((p) => String(p.Type) !== "String").map((p) => p.Name!);
  return (
    <Page title="Execute automation" icon={ICONS.automation} back={back}>
      <Section title="Runbook">
        {docs.ok ? (
          docs.value.length ? (
            <nav className="chips" aria-label="Runbooks">
              {docs.value.map((d) => (
                <Link key={d.Name} href={`/ssm/automation/start?document=${encodeURIComponent(d.Name!)}`} className={d.Name === document ? "tag active" : "tag"} aria-current={d.Name === document ? "true" : undefined}>
                  <span>{d.Name}</span>
                  {d.Owner && d.Owner !== "Amazon" && <b>own</b>}
                </Link>
              ))}
            </nav>
          ) : (
            <Empty icon={ICONS.document}>
              No Automation documents; <Link href="/ssm/documents">create one</Link>
            </Empty>
          )
        ) : (
          <ErrorNotice error={docs.error} />
        )}
        {doc?.ok && doc.value.Description && <p className="muted">{doc.value.Description}</p>}
      </Section>
      {doc && !doc.ok && <ErrorNotice error={doc.error} />}
      {doc?.ok && (
        <ActionForm action={startAutomation.bind(null, document!, lists)} submit="Execute" testId="start-automation">
          {params.map((p) => (
            <Field key={p.Name} label={p.Name!} hint={p.Description}>
              {String(p.Type) !== "String" ? (
                <textarea name={`param:${p.Name}`} rows={2} defaultValue={p.DefaultValue} className="code-editor" spellCheck={false} />
              ) : (
                <input name={`param:${p.Name}`} defaultValue={p.DefaultValue} />
              )}
            </Field>
          ))}
          <MoreFields>
          <div className="form-row">
            <Field label="Mode">
              <select name="mode" defaultValue="Auto">
                <option value="Auto">Simple execution</option>
                <option value="Interactive">Manual execution (step by step)</option>
              </select>
            </Field>
            <Field label="Document version" rule={StartAutomationExecution.DocumentVersion}>
              <input name="version" placeholder="$DEFAULT" />
            </Field>
          </div>
          </MoreFields>
          <input type="hidden" name="params" />
        </ActionForm>
      )}
    </Page>
  );
}
