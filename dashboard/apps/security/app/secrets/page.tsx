import { ListSecretsCommand } from "@aws-sdk/client-secrets-manager";
import { collect, load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, Field, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { secrets } from "../../lib/clients";
import { createSecret } from "./actions";

export const metadata: Metadata = { title: "Secrets Manager" };

export default async function Secrets() {
  const list = await load(async () => {
    const client = await secrets();
    return collect(
      (NextToken) => client.send(new ListSecretsCommand({ NextToken, IncludePlannedDeletion: true })),
      (r) => r.SecretList,
      (r) => r.NextToken,
    );
  });
  return (
    <>
      <PageHeader title="Secrets Manager" description="Secrets in the selected region. Values are sealed with KMS and only read when you open one." />
      <Section title="Create secret">
        <ActionForm action={createSecret} submit="Create secret" testId="create-secret">
          <div className="form-row">
            <Field label="Name">
              <input name="name" required pattern="[\w/+=.@\-]+" />
            </Field>
            <Field label="Description">
              <input name="description" />
            </Field>
          </div>
          <Field label="Secret value">
            <textarea name="value" placeholder='{"username": "app", "password": "..."}' />
          </Field>
        </ActionForm>
      </Section>
      <Section title={list.ok ? `Secrets (${list.value.length})` : "Secrets"}>
        {list.ok ? (
          <Table
            label="Secrets"
            rows={list.value}
            rowKey={(s) => s.ARN!}
            empty="No secrets in this region."
            columns={[
              { header: "Name", cell: (s) => <Link href={`/secrets/secret?id=${encodeURIComponent(s.ARN!)}`}>{s.Name}</Link> },
              { header: "Description", cell: (s) => s.Description ?? "" },
              {
                header: "Rotation",
                cell: (s) => (s.RotationEnabled ? <Badge tone="info">every {s.RotationRules?.AutomaticallyAfterDays ?? "?"} days</Badge> : <Badge>off</Badge>),
              },
              { header: "Last changed", cell: (s) => when(s.LastChangedDate) },
              { header: "", cell: (s) => s.DeletedDate && <Badge tone="bad">deletion scheduled</Badge> },
            ]}
          />
        ) : (
          <ErrorNotice error={list.error} />
        )}
      </Section>
    </>
  );
}
