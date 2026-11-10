import { DescribeUserCommand, ListGroupMembershipsForMemberCommand } from "@aws-sdk/client-identitystore";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Facts, Field, List, Page, Section, Segments, Sheet } from "@mws-dashboard/ui";
import { CreateUser } from "@mws-dashboard/ui/model/identitystore";
import { Pencil, Trash2, UserMinus, UserPlus } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, identitystore } from "../../../../lib/clients";
import { accounts as listAccounts, assignmentsForPrincipal, groups as listGroups, instance as loadInstance, permissionSets, userName } from "../../../../lib/sso";
import { addMembership, deleteMembership, deleteUser, updateUser } from "../../actions";
import { Assignments, Operations } from "../../parts";

type Props = { params: Promise<{ id: string }>; searchParams: Promise<{ tab?: string }> };

export const metadata: Metadata = { title: "User" };

export default async function User({ params, searchParams }: Props) {
  const { id } = await params;
  const { tab = "groups" } = await searchParams;
  const back = { href: "/identitycenter", label: "Users" };
  const data = await load(async () => {
    const inst = await loadInstance();
    if (!inst) throw new Error("Identity Center is not enabled in this Region");
    const store = inst.store;
    const c = await identitystore();
    const [user, member, groups, sets, accounts, assignments] = await Promise.all([
      c.send(new DescribeUserCommand({ IdentityStoreId: store, UserId: id })),
      all((NextToken) => c.send(new ListGroupMembershipsForMemberCommand({ IdentityStoreId: store, MemberId: { UserId: id }, NextToken })), (r) => r.GroupMemberships, (r) => r.NextToken),
      listGroups(store),
      inst.permissionSets ? permissionSets(inst.arn) : [],
      listAccounts(inst.owner),
      assignmentsForPrincipal(inst.arn, id, "USER"),
    ]);
    return { inst, user, member, groups, sets, accounts, assignments };
  });
  if (!data.ok) {
    return (
      <Page title="User" icon={ICONS.user} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { inst, user: u, member, groups, sets, accounts, assignments } = data.value;
  const groupName = new Map(groups.map((g) => [g.GroupId!, g.DisplayName!]));
  const joined = new Set(member.map((m) => m.GroupId));
  const email = u.Emails?.find((e) => e.Primary)?.Value ?? u.Emails?.[0]?.Value;
  const phone = u.PhoneNumbers?.find((p) => p.Primary)?.Value ?? u.PhoneNumbers?.[0]?.Value;
  const base = `/identitycenter/users/${id}`;
  const active = tab === "assignments" ? "assignments" : "groups";

  return (
    <Page
      title={u.UserName}
      icon={ICONS.user}
      back={back}
      subtitle={u.UserId}
      actions={
        <>
          <Sheet title="Edit user" label="Edit user" icon={<Pencil size={16} />} testId="edit-sso-user">
            <ActionForm action={updateUser.bind(null, inst.store, id)} submit="Save" testId="edit-sso-user">
              <Field label="Display name" rule={CreateUser.DisplayName}>
                <input name="display" required defaultValue={u.DisplayName} />
              </Field>
              <div className="form-row">
                <Field label="First name" rule={CreateUser.Name.fields?.GivenName}>
                  <input name="given" required defaultValue={u.Name?.GivenName} />
                </Field>
                <Field label="Last name" rule={CreateUser.Name.fields?.FamilyName}>
                  <input name="family" required defaultValue={u.Name?.FamilyName} />
                </Field>
              </div>
              <Field label="Email address" rule={CreateUser.Emails.item?.fields?.Value} format="email">
                <input name="email" type="email" defaultValue={email} />
              </Field>
              <Field label="Job title" rule={CreateUser.Title}>
                <input name="title" defaultValue={u.Title} />
              </Field>
              <Field label="Phone number" rule={CreateUser.PhoneNumbers.item?.fields?.Value} format="phone">
                <input name="phone" type="tel" defaultValue={phone} />
              </Field>
            </ActionForm>
          </Sheet>
          <ActionForm
            action={deleteUser.bind(null, inst.store, id, inst.arn, true)}
            submit="Delete user"
            icon={<Trash2 size={16} />}
            tone="danger"
            confirm={`Delete ${u.UserName}?${assignments.length ? ` Their ${assignments.length} assignments are removed.` : ""}`}
            testId="delete-sso-user"
          />
        </>
      }
    >
      <Facts
        items={[
          userName(u) !== u.UserName && ["Name", userName(u)],
          email && ["Email", email],
          u.Title && ["Job title", u.Title],
          phone && ["Phone", phone],
          u.UserStatus && u.UserStatus !== "ENABLED" && ["Status", u.UserStatus.toLowerCase()],
          ...(u.ExternalIds ?? []).map((x) => [`External id (${x.Issuer})`, x.Id] as [string, string]),
          u.CreatedAt && ["Created", ago(u.CreatedAt)],
        ]}
      />
      <Segments
        label="User tabs"
        items={[
          { label: "Groups", href: base, active: active === "groups", count: member.length },
          { label: "AWS accounts", href: `${base}?tab=assignments`, active: active === "assignments", count: assignments.length },
        ]}
      />
      {active === "groups" ? (
        <Section
          title="Groups"
          count={member.length}
          plain
          actions={
            <Sheet title="Add to group" label="Add user to groups" icon={<UserPlus size={16} />} testId="add-sso-user-to-group">
              <ActionForm action={addMembership.bind(null, inst.store, { user: id })} submit="Add" testId="add-sso-user-to-group">
                <Field label="Group">
                  <select name="group" required>
                    {groups
                      .filter((g) => !joined.has(g.GroupId))
                      .map((g) => (
                        <option key={g.GroupId} value={g.GroupId}>
                          {g.DisplayName}
                        </option>
                      ))}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          }
        >
          <List
            label="Groups"
            empty={<Empty icon={ICONS.users} />}
            rows={member.map((m) => ({
              key: m.MembershipId!,
              icon: <AwsIcon icon={ICONS.users} size={22} />,
              title: groupName.get(m.GroupId!) ?? m.GroupId,
              href: `/identitycenter/groups/${m.GroupId}`,
              actions: (
                <ActionForm
                  action={deleteMembership.bind(null, inst.store, m.MembershipId!, m.GroupId!, id)}
                  submit={`Remove from ${groupName.get(m.GroupId!) ?? m.GroupId}`}
                  icon={<UserMinus size={15} />}
                />
              ),
            }))}
          />
        </Section>
      ) : (
        <>
          <Operations instance={inst.arn} />
          <Assignments
            instance={inst.arn}
            rows={assignments.map((a) => ({ account: a.AccountId!, set: a.PermissionSetArn!, type: "USER", principal: id }))}
            names={new Map([[id, u.UserName!]])}
            sets={sets}
            accounts={accounts}
            fixed={{ principal: `USER:${id}` }}
            show="account"
          />
        </>
      )}
    </Page>
  );
}
