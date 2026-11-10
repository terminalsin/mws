import { DescribeDocumentCommand } from "@aws-sdk/client-ssm";
import { load } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Field, Page, Section } from "@mws-dashboard/ui";
import { SendCommand } from "@mws-dashboard/ui/model/ssm";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ssm } from "../../../../lib/clients";
import { listDocuments, listNodes, nodeName } from "../../../../lib/nodes";
import { sendCommand } from "../actions";

export const metadata: Metadata = { title: "Run a command" };

type Props = { searchParams: Promise<{ document?: string; instance?: string }> };

/** AWS's "Run a command" page: pick a Command document, fill in its own
 * parameters, choose the nodes. */
export default async function Send({ searchParams }: Props) {
  const { document = "AWS-RunShellScript", instance } = await searchParams;
  const back = { href: "/ssm/commands", label: "Run Command" };
  const [docs, nodes, doc] = await Promise.all([
    load(() => listDocuments([{ Key: "DocumentType", Values: ["Command"] }])),
    load(listNodes),
    load(async () => (await (await ssm()).send(new DescribeDocumentCommand({ Name: document }))).Document!),
  ]);
  const q = (d: string) => `/ssm/commands/send?document=${encodeURIComponent(d)}${instance ? `&instance=${encodeURIComponent(instance)}` : ""}`;
  const online = nodes.ok ? nodes.value.filter((n) => n.PingStatus === "Online") : [];
  const params = doc.ok ? (doc.value.Parameters ?? []) : [];
  const lists = params.filter((p) => p.Type === "StringList").map((p) => p.Name!);
  return (
    <Page title="Run a command" icon={ICONS.runCommand} back={back}>
      <Section title="Command document">
        {docs.ok ? (
          <nav className="chips" aria-label="Command documents">
            {docs.value.map((d) => (
              <Link key={d.Name} href={q(d.Name!)} className={d.Name === document ? "tag active" : "tag"} aria-current={d.Name === document ? "true" : undefined}>
                <span>{d.Name}</span>
                {d.Owner && d.Owner !== "Amazon" && <b>own</b>}
              </Link>
            ))}
          </nav>
        ) : (
          <ErrorNotice error={docs.error} />
        )}
        {doc.ok && doc.value.Description && <p className="muted">{doc.value.Description}</p>}
      </Section>
      {!doc.ok ? (
        <ErrorNotice error={doc.error} />
      ) : (
        <ActionForm action={sendCommand.bind(null, document, lists)} submit="Run" testId="send-command">
          {params.map((p) => {
            const multi = p.Type === "StringList" || /commands|script/i.test(p.Name ?? "");
            return (
              <Field key={p.Name} label={p.Name!} hint={p.Description}>
                {multi ? (
                  <textarea name={`param:${p.Name}`} rows={p.Name === "commands" ? 5 : 2} defaultValue={p.DefaultValue} className="code-editor" spellCheck={false} placeholder={p.Name === "commands" ? "echo hello\nuname -a" : undefined} />
                ) : (
                  <input name={`param:${p.Name}`} defaultValue={p.DefaultValue} />
                )}
              </Field>
            );
          })}
          <fieldset className="checks" aria-label="Nodes">
            <legend>Nodes</legend>
            {online.map((n) => (
              <label key={n.InstanceId} className="check">
                <input type="checkbox" name="instances" value={n.InstanceId} defaultChecked={n.InstanceId === instance || online.length === 1} /> {nodeName(n)}
                {nodeName(n) !== n.InstanceId && <span className="muted"> {n.InstanceId}</span>}
              </label>
            ))}
            {online.length === 0 && <span className="muted">No managed node is online</span>}
          </fieldset>
          <Field label="Or targets" hint="tag:env=prod, InstanceIds=i-1,i-2 (one a line)" member="Targets">
            <textarea name="targets" rows={2} placeholder="tag:env=prod" />
          </Field>
          <div className="form-row">
            <Field label="Comment" rule={SendCommand.Comment}>
              <input name="comment" />
            </Field>
            <Field label="Timeout (seconds)" rule={SendCommand.TimeoutSeconds}>
              <input name="timeout" type="number" placeholder="3600" />
            </Field>
          </div>
          <div className="form-row">
            <Field label="Concurrency" rule={SendCommand.MaxConcurrency}>
              <input name="maxConcurrency" placeholder="50" />
            </Field>
            <Field label="Error threshold" rule={SendCommand.MaxErrors}>
              <input name="maxErrors" placeholder="0" />
            </Field>
            <Field label="Document version" rule={SendCommand.DocumentVersion}>
              <input name="version" placeholder="$DEFAULT" />
            </Field>
          </div>
        </ActionForm>
      )}
    </Page>
  );
}
