import { ActionForm, AwsIcon, CodeBlock, Empty, Field, Facts, List, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { Globe, KeyRound, Trash2 } from "lucide-react";
import Link from "next/link";

import { addPermission, removePermission } from "../../routes/lambda/actions";
import { actions, condition, principals, sourceArn, type Statement } from "../lambda";
import { arnHref, arnName } from "../links";
import { PERMISSION_ACTION, PRINCIPAL, SOURCE_ACCOUNT, SOURCE_ARN, STATEMENT_ID } from "../rules";
import { serviceIcon } from "./triggers";

const SERVICE_PRINCIPALS = ["sns.amazonaws.com", "events.amazonaws.com", "s3.amazonaws.com", "apigateway.amazonaws.com", "logs.amazonaws.com", "sqs.amazonaws.com", "elasticloadbalancing.amazonaws.com", "cognito-idp.amazonaws.com", "iot.amazonaws.com"];

export function Permissions({
  name,
  role,
  statements,
  qualifiers,
  sources,
}: {
  name: string;
  role?: string;
  statements: Statement[];
  qualifiers: string[];
  sources: string[];
}) {
  const roleName = role?.split("/").pop();
  return (
    <>
      <Section title="Execution role">
        <Facts
          items={[
            ["Role", <Link key="r" href={`/iam/roles/${encodeURIComponent(roleName ?? "")}`}>{roleName}</Link>],
          ]}
        />
      </Section>
      <Section
        title="Resource-based policy"
        count={statements.length}
        plain
        actions={
          <Sheet title="Add permission" label="Add permission" testId="add-permission">
            <ActionForm action={addPermission.bind(null, name)} submit="Save" testId="add-permission">
              <div className="form-row">
                <Field label="Statement ID" rule={STATEMENT_ID} taken={statements.map((s) => s.Sid ?? "")} unique member="StatementId">
                  <input name="sid" required spellCheck={false} />
                </Field>
                {qualifiers.length > 0 && (
                  <Field label="Version or alias">
                    <select name="qualifier" defaultValue="">
                      <option value="">Unqualified</option>
                      {qualifiers.map((q) => (
                        <option key={q}>{q}</option>
                      ))}
                    </select>
                  </Field>
                )}
              </div>
              <Field label="Principal" rule={PRINCIPAL} known={SERVICE_PRINCIPALS} member="Principal">
                <input name="principal" required list="principals" placeholder="sns.amazonaws.com" spellCheck={false} />
              </Field>
              <datalist id="principals">
                {SERVICE_PRINCIPALS.map((p) => (
                  <option key={p} value={p} />
                ))}
              </datalist>
              <Field label="Source ARN" rule={SOURCE_ARN} known={sources} member="SourceArn">
                <input name="sourceArn" spellCheck={false} placeholder="arn:aws:sns:…" />
              </Field>
              <div className="form-row">
                <Field label="Source account" rule={SOURCE_ACCOUNT} member="SourceAccount">
                  <input name="sourceAccount" inputMode="numeric" />
                </Field>
                <Field label="Action" rule={PERMISSION_ACTION} member="Action">
                  <select name="action" defaultValue="lambda:InvokeFunction">
                    <option>lambda:InvokeFunction</option>
                    <option>lambda:InvokeFunctionUrl</option>
                    <option>lambda:GetFunction</option>
                    <option>lambda:*</option>
                  </select>
                </Field>
              </div>
            </ActionForm>
          </Sheet>
        }
      >
        <List
          label="Policy statements"
          empty={<Empty icon="resource/AWSIdentityAccessManagementPermissions" />}
          rows={statements.map((s) => {
            const who = principals(s);
            const service = who.find((p) => p.endsWith(".amazonaws.com"))?.replace(/\.amazonaws\.com$/, "");
            const source = sourceArn(s);
            const href = arnHref(source);
            const qualifier = (Array.isArray(s.Resource) ? s.Resource[0] : s.Resource)?.split(":")[7];
            const publicUrl = who.includes("*");
            return {
              key: s.Sid ?? JSON.stringify(s),
              icon: service ? <AwsIcon icon={serviceIcon(service)} size={24} /> : publicUrl ? <Globe size={18} aria-hidden /> : <KeyRound size={18} aria-hidden />,
              title: s.Sid,
              subtitle: (
                <>
                  {who.join(", ")} · {actions(s).join(", ")}
                  {source && <> · {href ? <Link href={href}>{arnName(source)}</Link> : source}</>}
                  {condition(s, "AWS:SourceAccount") && <> · {condition(s, "AWS:SourceAccount")}</>}
                  <details>
                    <summary>statement</summary>
                    <CodeBlock value={JSON.stringify(s)} />
                  </details>
                </>
              ),
              meta: (
                <>
                  {qualifier && <Pill>{qualifier}</Pill>}
                  {s.Effect === "Deny" && <Pill tone="bad">Deny</Pill>}
                  {publicUrl && <Pill tone="warn">public</Pill>}
                </>
              ),
              actions: s.Sid ? (
                <ActionForm action={removePermission.bind(null, name, s.Sid, qualifier)} submit={`Remove ${s.Sid}`} icon={<Trash2 size={15} aria-hidden />} tone="danger" confirm={`Remove statement ${s.Sid}?`} />
              ) : undefined,
            };
          })}
        />
      </Section>
    </>
  );
}
