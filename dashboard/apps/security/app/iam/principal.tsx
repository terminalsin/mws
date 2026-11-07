import {
  GetRoleCommand,
  GetUserCommand,
  ListAttachedRolePoliciesCommand,
  ListAttachedUserPoliciesCommand,
  ListRolePoliciesCommand,
  ListUserPoliciesCommand,
} from "@aws-sdk/client-iam";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, CodeBlock, ErrorNotice, Field, KeyValue, PageHeader, Section, Table } from "@mws-dashboard/ui";

import { iam, policyDocument } from "../../lib/clients";
import { attachPolicy, deletePrincipal, detachPolicy } from "./actions";

/** The detail page of a role or a user: who it is, and what it may do. */
export async function Principal({ kind, name }: { kind: "role" | "user"; name: string }) {
  const client = await iam();
  const data = await load(async () => {
    if (kind === "role") {
      const [role, attached, inline] = await Promise.all([
        client.send(new GetRoleCommand({ RoleName: name })),
        client.send(new ListAttachedRolePoliciesCommand({ RoleName: name })),
        client.send(new ListRolePoliciesCommand({ RoleName: name })),
      ]);
      const r = role.Role!;
      return {
        arn: r.Arn!,
        id: r.RoleId!,
        created: r.CreateDate,
        extra: [
          ["Max session", `${r.MaxSessionDuration ?? 3600}s`],
          ["Last used", when(r.RoleLastUsed?.LastUsedDate)],
        ] as [string, string][],
        trust: policyDocument(r.AssumeRolePolicyDocument),
        tags: r.Tags ?? [],
        attached: attached.AttachedPolicies ?? [],
        inline: inline.PolicyNames ?? [],
      };
    }
    const [user, attached, inline] = await Promise.all([
      client.send(new GetUserCommand({ UserName: name })),
      client.send(new ListAttachedUserPoliciesCommand({ UserName: name })),
      client.send(new ListUserPoliciesCommand({ UserName: name })),
    ]);
    const u = user.User!;
    return {
      arn: u.Arn!,
      id: u.UserId!,
      created: u.CreateDate,
      extra: [["Password last used", when(u.PasswordLastUsed)]] as [string, string][],
      trust: undefined,
      tags: u.Tags ?? [],
      attached: attached.AttachedPolicies ?? [],
      inline: inline.PolicyNames ?? [],
    };
  });
  const crumbs = [{ label: "IAM", href: kind === "role" ? "/iam?tab=roles" : "/iam" }];
  if (!data.ok) {
    return (
      <>
        <PageHeader title={name} crumbs={crumbs} />
        <ErrorNotice error={data.error} />
      </>
    );
  }
  const p = data.value;
  return (
    <>
      <PageHeader title={name} crumbs={crumbs} description={<code>{p.arn}</code>} />
      <Section title="Summary">
        <KeyValue
          items={[
            ["Type", kind],
            ["Unique ID", <code>{p.id}</code>],
            ["Created", when(p.created)],
            ...p.extra,
            [
              "Tags",
              p.tags.length ? (
                <span className="chips">
                  {p.tags.map((t) => (
                    <Badge key={t.Key}>
                      {t.Key}={t.Value}
                    </Badge>
                  ))}
                </span>
              ) : (
                "none"
              ),
            ],
          ]}
        />
      </Section>
      {p.trust && (
        <Section title="Trust policy">
          <CodeBlock value={p.trust} label="Trust policy" />
        </Section>
      )}
      <Section title="Attached managed policies">
        <Table
          label="Attached policies"
          rows={p.attached}
          rowKey={(a) => a.PolicyArn!}
          empty="No managed policies attached."
          columns={[
            { header: "Name", cell: (a) => a.PolicyName },
            { header: "ARN", className: "wrap", cell: (a) => <code>{a.PolicyArn}</code> },
            {
              header: "",
              cell: (a) => <ActionForm action={detachPolicy.bind(null, kind, name, a.PolicyArn!)} submit="Detach" tone="danger" inline />,
            },
          ]}
        />
        <div style={{ marginTop: 12 }}>
          <ActionForm action={attachPolicy.bind(null, kind, name)} submit="Attach" inline testId="attach-policy">
            <Field label="Policy ARN">
              <input name="policyArn" required size={56} placeholder="arn:aws:iam::aws:policy/ReadOnlyAccess" />
            </Field>
          </ActionForm>
        </div>
      </Section>
      <Section title="Inline policies">
        {p.inline.length ? (
          <div className="chips">
            {p.inline.map((n) => (
              <Badge key={n}>{n}</Badge>
            ))}
          </div>
        ) : (
          <p className="muted">No inline policies.</p>
        )}
      </Section>
      <Section title="Delete">
        <ActionForm
          action={deletePrincipal.bind(null, kind, name)}
          submit={`Delete ${kind}`}
          tone="danger"
          confirm={`Delete ${kind} ${name}? IAM refuses while policies are attached.`}
          inline
        />
      </Section>
    </>
  );
}
