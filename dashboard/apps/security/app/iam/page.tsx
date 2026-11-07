import { ListGroupsCommand, ListPoliciesCommand, ListRolesCommand, ListUsersCommand } from "@aws-sdk/client-iam";
import { search } from "@mws-dashboard/ai";
import { ago, collect, frameInfo, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Metric, Metrics, Page, Pill, Section, Segments, Sheet } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, iam, policyDocument, principalIcon, trust } from "../../lib/clients";
import { createGroup, createPolicy, createRole, createUser } from "./actions";

export const metadata: Metadata = { title: "IAM" };

type Props = { searchParams: Promise<{ tab?: string; q?: string }> };

const TRUST_SECTIONS = [
  { id: "service", title: "Service roles" },
  { id: "account", title: "Account roles" },
  { id: "cross-account", title: "Cross-account roles" },
  { id: "federated", title: "Federated roles" },
] as const;

async function everything() {
  const client = await iam();
  const [users, roles, groups, policies] = await Promise.all([
    collect((Marker) => client.send(new ListUsersCommand({ Marker })), (r) => r.Users, (r) => (r.IsTruncated ? r.Marker : undefined)),
    collect((Marker) => client.send(new ListRolesCommand({ Marker })), (r) => r.Roles, (r) => (r.IsTruncated ? r.Marker : undefined)),
    collect((Marker) => client.send(new ListGroupsCommand({ Marker })), (r) => r.Groups, (r) => (r.IsTruncated ? r.Marker : undefined)),
    collect((Marker) => client.send(new ListPoliciesCommand({ Marker, Scope: "Local" })), (r) => r.Policies, (r) => (r.IsTruncated ? r.Marker : undefined)),
  ]);
  return { users, roles, groups, policies };
}

export default async function Iam({ searchParams }: Props) {
  const { tab = "users", q = "" } = await searchParams;
  const [data, info] = await Promise.all([load(everything), frameInfo()]);
  if (!data.ok) {
    return (
      <Page title="IAM" icon={ICONS.iam}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { users, roles, groups, policies } = data.value;
  const create = {
    users: (
      <Sheet title="New user" label="Create user" testId="create-user">
        <ActionForm action={createUser} submit="Create" testId="create-user">
          <Field label="Name">
            <input name="name" required pattern="[\w+=,.@\-]+" autoFocus />
          </Field>
          <Field label="Path">
            <input name="path" placeholder="/" />
          </Field>
        </ActionForm>
      </Sheet>
    ),
    roles: (
      <Sheet title="New role" label="Create role" testId="create-role">
        <ActionForm action={createRole} submit="Create" testId="create-role">
          <Field label="Name">
            <input name="name" required pattern="[\w+=,.@\-]+" autoFocus />
          </Field>
          <Field label="Trusted service">
            <input name="service" defaultValue="lambda.amazonaws.com" list="principals" />
          </Field>
          <datalist id="principals">
            {["lambda.amazonaws.com", "ec2.amazonaws.com", "ecs-tasks.amazonaws.com", "states.amazonaws.com", "events.amazonaws.com", "firehose.amazonaws.com"].map((p) => (
              <option key={p} value={p} />
            ))}
          </datalist>
          <Field label="Or a trust policy">
            <textarea name="trust" placeholder='{"Version": "2012-10-17", "Statement": [...]}' />
          </Field>
        </ActionForm>
      </Sheet>
    ),
    groups: (
      <Sheet title="New group" label="Create group">
        <ActionForm action={createGroup} submit="Create">
          <Field label="Name">
            <input name="name" required pattern="[\w+=,.@\-]+" />
          </Field>
        </ActionForm>
      </Sheet>
    ),
    policies: (
      <Sheet title="New policy" label="Create policy" testId="create-policy">
        <ActionForm action={createPolicy} submit="Create" testId="create-policy">
          <Field label="Name">
            <input name="name" required pattern="[\w+=,.@\-]+" />
          </Field>
          <textarea
            name="document"
            rows={12}
            aria-label="Policy document"
            defaultValue={JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "s3:GetObject", Resource: "*" }] }, null, 2)}
          />
        </ActionForm>
      </Sheet>
    ),
  } as const;

  let body;
  if (tab === "roles") {
    const classified = roles.map((r) => ({ role: r, ...trust(policyDocument(r.AssumeRolePolicyDocument), info.account) }));
    body = (
      <Curated
        label="Roles"
        sections={TRUST_SECTIONS.map((s) => ({ id: s.id, title: s.title, items: classified.filter((c) => c.kind === s.id) }))}
        empty={<Empty icon={ICONS.role} />}
        row={({ role, services }) => ({
          key: role.RoleId!,
          icon: <AwsIcon icon={services[0] ? principalIcon(services[0]) : ICONS.role} size={24} />,
          title: role.RoleName,
          subtitle: services.join(", ") || role.Description,
          href: `/iam/roles/${encodeURIComponent(role.RoleName!)}`,
          meta: <span>{role.RoleLastUsed?.LastUsedDate ? `used ${ago(role.RoleLastUsed.LastUsedDate)}` : ago(role.CreateDate)}</span>,
        })}
      />
    );
  } else if (tab === "groups") {
    body = (
      <List
        label="Groups"
        empty={<Empty icon={ICONS.users} />}
        rows={groups.map((g) => ({
          key: g.GroupId!,
          icon: <AwsIcon icon={ICONS.users} size={24} />,
          title: g.GroupName,
          href: `/iam/groups/${encodeURIComponent(g.GroupName!)}`,
          meta: ago(g.CreateDate),
        }))}
      />
    );
  } else if (tab === "policies") {
    const aws = q
      ? await load(async () => {
          const client = await iam();
          const all = await collect(
            (Marker) => client.send(new ListPoliciesCommand({ Marker, Scope: "AWS" })),
            (r) => r.Policies,
            (r) => (r.IsTruncated ? r.Marker : undefined),
            5000,
          );
          return search(q, all.map((p) => ({ ...p, text: `${p.PolicyName} ${p.Description ?? ""} ${p.Path}` })), 30);
        })
      : null;
    const local = q ? await search(q, policies.map((p) => ({ ...p, text: `${p.PolicyName} ${p.Description ?? ""}` })), 50) : policies;
    const row = (p: (typeof policies)[number]) => ({
      key: p.Arn!,
      icon: <AwsIcon icon={ICONS.policy} size={24} />,
      title: p.PolicyName,
      subtitle: p.Description,
      href: `/iam/policy?arn=${encodeURIComponent(p.Arn!)}`,
      meta: (p.AttachmentCount ?? 0) > 0 ? <Pill>{p.AttachmentCount}</Pill> : <Pill tone="warn">unattached</Pill>,
    });
    body = (
      <>
        <form className="search-page-form" action="/security/iam">
          <input type="hidden" name="tab" value="policies" />
          <input name="q" defaultValue={q} placeholder="Find a policy, including AWS managed ones" aria-label="Find a policy" />
        </form>
        <Section title="Customer managed" count={local.length} plain>
          <List label="Customer managed policies" rows={local.map(row)} empty={<Empty icon={ICONS.policy} />} />
        </Section>
        {aws && (
          <Section title="AWS managed" count={aws.ok ? aws.value.length : undefined} plain>
            {aws.ok ? <List label="AWS managed policies" rows={aws.value.map(row)} empty={<Empty>—</Empty>} /> : <ErrorNotice error={aws.error} />}
          </Section>
        )}
      </>
    );
  } else {
    body = (
      <List
        label="Users"
        empty={<Empty icon={ICONS.user} />}
        rows={users.map((u) => ({
          key: u.UserId!,
          icon: <AwsIcon icon={ICONS.user} size={24} />,
          title: u.UserName,
          subtitle: u.Path !== "/" ? u.Path : undefined,
          href: `/iam/users/${encodeURIComponent(u.UserName!)}`,
          meta: u.PasswordLastUsed ? `signed in ${ago(u.PasswordLastUsed)}` : ago(u.CreateDate),
        }))}
      />
    );
  }

  return (
    <Page title="IAM" icon={ICONS.iam} actions={create[tab as keyof typeof create] ?? create.users}>
      <Metrics>
        <Metric label="Users" value={users.length} href="/security/iam" />
        <Metric label="Roles" value={roles.length} href="/security/iam?tab=roles" />
        <Metric label="Groups" value={groups.length} href="/security/iam?tab=groups" />
        <Metric label="Policies" value={policies.length} href="/security/iam?tab=policies" />
      </Metrics>
      <Segments
        items={[
          { label: "Users", href: "/iam", active: tab === "users" },
          { label: "Roles", href: "/iam?tab=roles", active: tab === "roles" },
          { label: "Groups", href: "/iam?tab=groups", active: tab === "groups" },
          { label: "Policies", href: "/iam?tab=policies", active: tab === "policies" },
        ]}
      />
      {body}
    </Page>
  );
}
