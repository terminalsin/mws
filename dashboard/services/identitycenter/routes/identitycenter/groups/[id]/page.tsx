import { DescribeGroupCommand } from "@aws-sdk/client-identitystore";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Section, Segments, Sheet } from "@mws-dashboard/ui";
import { CreateGroup } from "@mws-dashboard/ui/model/identitystore";
import { Pencil, Trash2, UserMinus, UserPlus } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, identitystore } from "../../../../lib/clients";
import { accounts as listAccounts, assignmentsForPrincipal, instance as loadInstance, memberships, permissionSets, users as listUsers, userName } from "../../../../lib/sso";
import { addMembership, deleteGroup, deleteMembership, updateGroup } from "../../actions";
import { Assignments, Operations } from "../../parts";

type Props = { params: Promise<{ id: string }>; searchParams: Promise<{ tab?: string }> };

export const metadata: Metadata = { title: "Group" };

export default async function Group({ params, searchParams }: Props) {
  const { id } = await params;
  const { tab = "users" } = await searchParams;
  const back = { href: "/identitycenter?tab=groups", label: "Groups" };
  const data = await load(async () => {
    const inst = await loadInstance();
    if (!inst) throw new Error("Identity Center is not enabled in this Region");
    const c = await identitystore();
    const [group, members, users, sets, accounts, assignments] = await Promise.all([
      c.send(new DescribeGroupCommand({ IdentityStoreId: inst.store, GroupId: id })),
      memberships(inst.store, id),
      listUsers(inst.store),
      inst.permissionSets ? permissionSets(inst.arn) : [],
      listAccounts(inst.owner),
      assignmentsForPrincipal(inst.arn, id, "GROUP"),
    ]);
    return { inst, group, members, users, sets, accounts, assignments };
  });
  if (!data.ok) {
    return (
      <Page title="Group" icon={ICONS.users} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { inst, group: g, members, users, sets, accounts, assignments } = data.value;
  const byId = new Map(users.map((u) => [u.UserId!, u]));
  const inGroup = new Set(members.map((m) => m.MemberId?.UserId));
  const base = `/identitycenter/groups/${id}`;
  const active = tab === "assignments" ? "assignments" : "users";

  return (
    <Page
      title={g.DisplayName}
      icon={ICONS.users}
      back={back}
      subtitle={g.GroupId}
      actions={
        <>
          <Sheet title="Edit group" label="Edit group" icon={<Pencil size={16} />} testId="edit-sso-group">
            <ActionForm action={updateGroup.bind(null, inst.store, id)} submit="Save" testId="edit-sso-group">
              <Field label="Group name" rule={{ ...CreateGroup.DisplayName, takenIgnoreCase: true }}>
                <input name="name" required defaultValue={g.DisplayName} />
              </Field>
              <Field label="Description" rule={CreateGroup.Description}>
                <input name="description" defaultValue={g.Description} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={deleteGroup.bind(null, inst.store, id, inst.arn, true)}
            submit="Delete group"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${g.DisplayName}?${assignments.length ? ` Its ${assignments.length} assignments are removed.` : ""}`}
            testId="delete-sso-group"
          />
        </>
      }
    >
      <Facts
        items={[
          g.Description && ["Description", g.Description],
          ...(g.ExternalIds ?? []).map((x) => [`External id (${x.Issuer})`, x.Id] as [string, string]),
          g.CreatedAt && ["Created", ago(g.CreatedAt)],
        ]}
      />
      <Segments
        label="Group tabs"
        items={[
          { label: "Users", href: base, active: active === "users", count: members.length },
          { label: "AWS accounts", href: `${base}?tab=assignments`, active: active === "assignments", count: assignments.length },
        ]}
      />
      {active === "users" ? (
        <Section
          title="Users"
          count={members.length}
          plain
          actions={
            <Sheet title="Add users to group" label="Add users to group" icon={<UserPlus size={16} />} testId="add-sso-member">
              <ActionForm action={addMembership.bind(null, inst.store, { group: id })} submit="Add" testId="add-sso-member">
                <Field label="User">
                  <select name="user" required>
                    {users
                      .filter((u) => !inGroup.has(u.UserId))
                      .map((u) => (
                        <option key={u.UserId} value={u.UserId}>
                          {u.UserName}
                        </option>
                      ))}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Members"
            empty={<Empty icon={ICONS.user} />}
            rows={members.map((m) => {
              const u = byId.get(m.MemberId?.UserId ?? "");
              return {
                key: m.MembershipId!,
                icon: <AwsIcon icon={ICONS.user} size={22} />,
                title: u?.UserName ?? m.MemberId?.UserId,
                subtitle: u && userName(u) !== u.UserName ? userName(u) : undefined,
                href: `/identitycenter/users/${m.MemberId?.UserId}`,
                actions: (
                  <ActionForm
                    action={deleteMembership.bind(null, inst.store, m.MembershipId!, id, m.MemberId?.UserId ?? "")}
                    submit={`Remove ${u?.UserName ?? "member"}`}
                    icon={<UserMinus size={15} />}
                  />
                ),
              };
            })}
          />
        </Section>
      ) : (
        <>
          <Operations instance={inst.arn} />
          <Assignments
            instance={inst.arn}
            rows={assignments.map((a) => ({ account: a.AccountId!, set: a.PermissionSetArn!, type: "GROUP", principal: id }))}
            names={new Map([[id, g.DisplayName!]])}
            sets={sets}
            accounts={accounts}
            fixed={{ principal: `GROUP:${id}` }}
            show="account"
          />
        </>
      )}
    </Page>
  );
}
