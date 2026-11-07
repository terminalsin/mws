import { ListPoliciesCommand, ListRolesCommand, ListUsersCommand } from "@aws-sdk/client-iam";
import { collect, load, when } from "@mws-dashboard/aws";
import { ActionForm, ErrorNotice, Field, PageHeader, Section, Table, Tabs } from "@mws-dashboard/ui";
import type { Metadata } from "next";
import Link from "next/link";

import { iam } from "../../lib/clients";
import { createRole, createUser } from "./actions";

export const metadata: Metadata = { title: "IAM" };

type Props = { searchParams: Promise<{ tab?: string }> };

async function Users() {
  const client = await iam();
  const users = await load(() =>
    collect(
      (Marker) => client.send(new ListUsersCommand({ Marker })),
      (r) => r.Users,
      (r) => (r.IsTruncated ? r.Marker : undefined),
    ),
  );
  return (
    <>
      <Section title="Create user">
        <ActionForm action={createUser} submit="Create user" inline testId="create-user">
          <Field label="User name">
            <input name="name" required pattern="[\w+=,.@\-]+" />
          </Field>
          <Field label="Path">
            <input name="path" placeholder="/" />
          </Field>
        </ActionForm>
      </Section>
      <Section title="Users">
        {users.ok ? (
          <Table
            label="Users"
            rows={users.value}
            rowKey={(u) => u.UserId!}
            empty="No IAM users."
            columns={[
              { header: "Name", cell: (u) => <Link href={`/iam/users/${encodeURIComponent(u.UserName!)}`}>{u.UserName}</Link> },
              { header: "ARN", className: "wrap", cell: (u) => <code>{u.Arn}</code> },
              { header: "Created", cell: (u) => when(u.CreateDate) },
            ]}
          />
        ) : (
          <ErrorNotice error={users.error} />
        )}
      </Section>
    </>
  );
}

async function Roles() {
  const client = await iam();
  const roles = await load(() =>
    collect(
      (Marker) => client.send(new ListRolesCommand({ Marker })),
      (r) => r.Roles,
      (r) => (r.IsTruncated ? r.Marker : undefined),
    ),
  );
  return (
    <>
      <Section title="Create role">
        <ActionForm action={createRole} submit="Create role" testId="create-role">
          <Field label="Role name">
            <input name="name" required pattern="[\w+=,.@\-]+" />
          </Field>
          <Field label="Trust policy" hint="Leave empty to let Lambda assume the role.">
            <textarea name="trust" placeholder='{"Version": "2012-10-17", "Statement": [...]}' />
          </Field>
        </ActionForm>
      </Section>
      <Section title="Roles">
        {roles.ok ? (
          <Table
            label="Roles"
            rows={roles.value}
            rowKey={(r) => r.RoleId!}
            empty="No IAM roles."
            columns={[
              { header: "Name", cell: (r) => <Link href={`/iam/roles/${encodeURIComponent(r.RoleName!)}`}>{r.RoleName}</Link> },
              { header: "Path", cell: (r) => <code>{r.Path}</code> },
              { header: "Description", cell: (r) => r.Description ?? "" },
              { header: "Created", cell: (r) => when(r.CreateDate) },
            ]}
          />
        ) : (
          <ErrorNotice error={roles.error} />
        )}
      </Section>
    </>
  );
}

async function Policies({ scope }: { scope: "Local" | "AWS" }) {
  const client = await iam();
  const policies = await load(() =>
    collect(
      (Marker) => client.send(new ListPoliciesCommand({ Marker, Scope: scope })),
      (r) => r.Policies,
      (r) => (r.IsTruncated ? r.Marker : undefined),
      2000,
    ),
  );
  return (
    <Section title={scope === "AWS" ? "AWS managed policies" : "Customer managed policies"}>
      {policies.ok ? (
        <Table
          label="Policies"
          rows={policies.value}
          rowKey={(p) => p.Arn!}
          empty="No policies."
          columns={[
            { header: "Name", cell: (p) => p.PolicyName },
            { header: "ARN", className: "wrap", cell: (p) => <code>{p.Arn}</code> },
            { header: "Attachments", className: "num", cell: (p) => p.AttachmentCount ?? 0 },
            { header: "Updated", cell: (p) => when(p.UpdateDate) },
          ]}
        />
      ) : (
        <ErrorNotice error={policies.error} />
      )}
    </Section>
  );
}

export default async function Iam({ searchParams }: Props) {
  const tab = (await searchParams).tab ?? "users";
  return (
    <>
      <PageHeader title="IAM" description="Identities and policies of the current account. MWS evaluates these on every request." />
      <Tabs
        items={[
          { label: "Users", href: "/iam", active: tab === "users" },
          { label: "Roles", href: "/iam?tab=roles", active: tab === "roles" },
          { label: "Customer policies", href: "/iam?tab=policies", active: tab === "policies" },
          { label: "AWS managed policies", href: "/iam?tab=aws-policies", active: tab === "aws-policies" },
        ]}
      />
      {tab === "roles" ? <Roles /> : tab === "policies" ? <Policies scope="Local" /> : tab === "aws-policies" ? <Policies scope="AWS" /> : <Users />}
    </>
  );
}
