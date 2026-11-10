import { GetGroupPolicyCommand, GetRolePolicyCommand, GetUserPolicyCommand } from "@aws-sdk/client-iam";
import { load } from "@mws-dashboard/aws";
import { ActionForm, CodeBlock, ErrorNotice, Page, Section, Sheet, Field } from "@mws-dashboard/ui";
import { Pencil, Trash2 } from "lucide-react";

import { ICONS, iam, policyDocument } from "../../lib/clients";
import type { Kind } from "../../lib/iam";
import { RULES } from "../../lib/rules";
import { deleteInlinePolicy, updateInlinePolicy } from "./actions";

/** One inline policy of a role, user or group: its document, edited in place. */
export async function InlinePolicy({ kind, name, policy }: { kind: Kind; name: string; policy: string }) {
  const back = { href: `/iam/${kind}s/${encodeURIComponent(name)}`, label: name };
  const data = await load(async () => {
    const client = await iam();
    const out =
      kind === "role"
        ? await client.send(new GetRolePolicyCommand({ RoleName: name, PolicyName: policy }))
        : kind === "user"
          ? await client.send(new GetUserPolicyCommand({ UserName: name, PolicyName: policy }))
          : await client.send(new GetGroupPolicyCommand({ GroupName: name, PolicyName: policy }));
    return policyDocument(out.PolicyDocument);
  });
  if (!data.ok) {
    return (
      <Page title={policy} icon={ICONS.policy} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  return (
    <Page
      title={policy}
      icon={ICONS.policy}
      back={back}
      actions={
        <>
          <Sheet title={`Edit ${policy}`} label="Edit policy" icon={<Pencil size={16} />} testId="edit-inline-policy">
            <ActionForm action={updateInlinePolicy.bind(null, kind, name, policy)} submit="Save" testId="edit-inline-policy">
              <Field label="Document" rule={RULES.document}>
                <textarea name="document" rows={16} required aria-label="Policy document" defaultValue={pretty(data.value)} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={deleteInlinePolicy.bind(null, kind, name, policy, true)}
            submit="Delete policy"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${policy}?`}
            testId="delete-inline-policy"
          />
        </>
      }
    >
      <Section title="Policy document">
        <CodeBlock value={data.value} label="Policy document" />
      </Section>
    </Page>
  );
}

function pretty(doc: string | undefined) {
  try {
    return JSON.stringify(JSON.parse(doc ?? ""), null, 2);
  } catch {
    return doc ?? "";
  }
}
