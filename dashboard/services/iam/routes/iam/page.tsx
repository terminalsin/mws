import { ListGroupsCommand, ListPoliciesCommand, ListRolesCommand, ListUsersCommand } from "@aws-sdk/client-iam";
import { search } from "@mws-dashboard/ai";
import { ago, all, frameInfo, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, List, Page, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { Fingerprint, FlaskConical, Link2, Settings } from "lucide-react";
import { MoreFields } from "@mws-dashboard/ui/presets";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, iam, policyDocument, principalIcon, trust } from "../../lib/clients";
import { PolicyFields, RoleFields } from "../../lib/forms.tsx";
import { RULES } from "../../lib/rules";
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
    all((Marker) => client.send(new ListUsersCommand({ Marker })), (r) => r.Users, (r) => (r.IsTruncated ? r.Marker : undefined)),
    all((Marker) => client.send(new ListRolesCommand({ Marker })), (r) => r.Roles, (r) => (r.IsTruncated ? r.Marker : undefined)),
    all((Marker) => client.send(new ListGroupsCommand({ Marker })), (r) => r.Groups, (r) => (r.IsTruncated ? r.Marker : undefined)),
    all((Marker) => client.send(new ListPoliciesCommand({ Marker, Scope: "Local" })), (r) => r.Policies, (r) => (r.IsTruncated ? r.Marker : undefined)),
  ]);
  return { users, roles, groups, policies };
}

export default async function Iam({ searchParams }: Props) {
  const { tab = "users", q = "" } = await searchParams;
  const [data, info] = await Promise.all([load(everything), frameInfo()]);
  if (!data.ok) {
    return (
      <Page title={{ users: "Users", roles: "Roles", groups: "Groups", policies: "Policies" }[tab] ?? "Users"}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { users, roles, groups, policies } = data.value;
  const create = {
    users: (
      <Sheet title="New user" label="Create user" testId="create-user">
        <ActionForm action={createUser} submit="Create" testId="create-user">
          <Field label="Name" rule={RULES.userName} taken={users.map((u) => u.UserName!)} unique>
            <input name="name" required autoFocus />
          </Field>
          <MoreFields>
            <Field label="Path" rule={RULES.path}>
              <input name="path" placeholder="/" />
            </Field>
          </MoreFields>
        </ActionForm>
      </Sheet>
    ),
    roles: (
      <Sheet title="New role" label="Create role" testId="create-role">
        <ActionForm action={createRole} submit="Create" testId="create-role">
          <RoleFields taken={roles.map((r) => r.RoleName!)} account={info.account} />
        </ActionForm>
      </Sheet>
    ),
    groups: (
      <Sheet title="New group" label="Create group" testId="create-group">
        <ActionForm action={createGroup} submit="Create" testId="create-group">
          <Field label="Name" rule={RULES.groupName} taken={groups.map((g) => g.GroupName!)} unique>
            <input name="name" required autoFocus />
          </Field>
          <MoreFields>
            <Field label="Path" rule={RULES.path}>
              <input name="path" placeholder="/" />
            </Field>
          </MoreFields>
        </ActionForm>
      </Sheet>
    ),
    policies: (
      <Sheet title="New policy" label="Create policy" testId="create-policy">
        <ActionForm action={createPolicy} submit="Create" testId="create-policy">
          <PolicyFields taken={policies.map((p) => p.PolicyName!)} />
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
        empty={<Empty icon={ICONS.role} action={create.roles} />}
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
        empty={<Empty icon={ICONS.users} action={create.groups} />}
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
          const managed = await all(
            (Marker) => client.send(new ListPoliciesCommand({ Marker, Scope: "AWS" })),
            (r) => r.Policies,
            (r) => (r.IsTruncated ? r.Marker : undefined),
          );
          return search(q, managed.map((p) => ({ ...p, text: `${p.PolicyName} ${p.Description ?? ""} ${p.Path}` })), 30);
        })
      : null;
    const local = q ? await search(q, policies.map((p) => ({ ...p, text: `${p.PolicyName} ${p.Description ?? ""}` })), 50) : policies;
    const row = (p: (typeof policies)[number]) => ({
      key: p.Arn!,
      icon: <AwsIcon icon={ICONS.policy} size={24} />,
      title: p.PolicyName,
      subtitle: p.Description,
      href: `/iam/policy?arn=${encodeURIComponent(p.Arn!)}`,
      meta:
        (p.AttachmentCount ?? 0) > 0 ? (
          <Pill icon={<Link2 size={12} />} title={`Attached to ${p.AttachmentCount}`}>
            {p.AttachmentCount}
          </Pill>
        ) : (
          <Pill tone="warn">unattached</Pill>
        ),
    });
    body = (
      <>
        <form className="search-page-form" action="/iam">
          <input type="hidden" name="tab" value="policies" />
          <input name="q" defaultValue={q} placeholder="Find a policy, including AWS managed ones" aria-label="Find a policy" />
        </form>
        <Section title="Customer managed" count={local.length} plain>
          <List label="Customer managed policies" rows={local.map(row)} empty={<Empty icon={ICONS.policy} action={q ? undefined : create.policies} />} />
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
        empty={<Empty icon={ICONS.user} action={create.users} />}
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
    <Page
      title={{ users: "Users", roles: "Roles", groups: "Groups", policies: "Policies" }[tab] ?? "Users"}
      actions={
        <>
          <Link className="icon-button plain" href="/iam/simulator" aria-label="Policy simulator" title="Policy simulator">
            <FlaskConical size={16} aria-hidden />
          </Link>
          {tab === "roles" && (
            <Link className="icon-button plain" href="/iam/providers" aria-label="Identity providers" title="Identity providers">
              <Fingerprint size={16} aria-hidden />
            </Link>
          )}
          <Link className="icon-button plain" href="/iam/settings" aria-label="Account settings" title="Account settings">
            <Settings size={16} aria-hidden />
          </Link>
          {create[tab as keyof typeof create] ?? create.users}
        </>
      }
    >
      {body}
    </Page>
  );
}
