import { ActionForm, CodeBlock, Field, Section, Sheet } from "@mws-dashboard/ui";
import { Pencil, Trash2 } from "lucide-react";

import { deletePolicy, savePolicy } from "../routes/codeartifact/actions";

const SAMPLE = (resource: string) =>
  JSON.stringify(
    {
      Version: "2012-10-17",
      Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::111122223333:root" }, Action: ["codeartifact:ReadFromRepository"], Resource: resource }],
    },
    null,
    2,
  );

/** A domain's or repository's resource policy, with edit and remove. */
export function PolicySection({
  kind,
  domain,
  owner,
  repository,
  arn,
  policy,
}: {
  kind: "domain" | "repository";
  domain: string;
  owner?: string;
  repository?: string;
  arn?: string;
  policy?: string;
}) {
  let pretty = policy;
  try {
    if (policy) pretty = JSON.stringify(JSON.parse(policy), null, 2);
  } catch {
    // Shown as stored.
  }
  return (
    <Section
      title={kind === "domain" ? "Domain policy" : "Repository policy"}
      actions={
        <>
          <Sheet title={kind === "domain" ? "Domain policy" : "Repository policy"} label="Edit policy" icon={<Pencil size={15} />} testId={`${kind}-policy`}>
            <ActionForm action={savePolicy.bind(null, kind, domain, owner, repository)} submit="Save policy" testId={`${kind}-policy`}>
              <Field label="Policy" format="json">
                <textarea name="policy" rows={14} className="code-editor" spellCheck={false} required defaultValue={pretty ?? SAMPLE(arn ?? "*")} />
              </Field>
            </ActionForm>
          </Sheet>
          {policy && (
            <ActionForm
              action={deletePolicy.bind(null, kind, domain, owner, repository)}
              submit="Remove policy"
              icon={<Trash2 size={15} />}
              tone="danger"
              confirm="Remove the policy?"
            />
          )}
        </>
      }
    >
      {pretty ? <CodeBlock value={pretty} label="Policy" /> : <p className="muted">No policy: only this account's identities have access.</p>}
    </Section>
  );
}
