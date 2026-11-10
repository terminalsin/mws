import { ListManagedPoliciesInPermissionSetCommand } from "@aws-sdk/client-sso-admin";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CopyButton, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateGroup, CreateUser } from "@mws-dashboard/ui/model/identitystore";
import { CreatePermissionSet } from "@mws-dashboard/ui/model/sso-admin";
import { RefreshCw, Timer, Trash2, Users } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ssoAdmin } from "../../lib/clients";
import { duration, groups as listGroups, instance as loadInstance, memberships, outdated, permissionSets, users as listUsers, userName } from "../../lib/sso";
import { createGroup, createPermissionSet, createUser, deleteGroup, deletePermissionSet, deleteUser, enableInstance, enablePermissionSets, provisionPermissionSet } from "./actions";
import { Links } from "./parts";
import { POLICIES } from "../../lib/policies";

export const metadata: Metadata = { title: "IAM Identity Center" };

type Props = { searchParams: Promise<{ tab?: string }> };

// The identity store's patterns allow any visible character; spell out what
// they reject. It compares user and group names ignoring case.
const USERNAME: Rule = { ...CreateUser.UserName, hint: "No spaces", takenIgnoreCase: true };
const PERMISSION_SET_NAME: Rule = { ...CreatePermissionSet.Name, hint: "Letters, digits and +=,.@-_", generate: "name" };
const GROUP_NAME: Rule = { ...CreateGroup.DisplayName, generate: "name", takenIgnoreCase: true };
const HOURS: Rule = { type: "number", min: 1, max: 12 };


export default async function IdentityCenter({ searchParams }: Props) {
  const { tab = "users" } = await searchParams;
  const found = await load(loadInstance);
  const title = tab === "groups" ? "Groups" : tab === "permissionsets" ? "Permission sets" : "Users";
  if (!found.ok) {
    return (
      <Page title="IAM Identity Center">
        <ErrorNotice error={found.error} />
      </Page>
    );
  }
  if (!found.value) {
    return (
      <Page title="IAM Identity Center">
        <Empty icon={ICONS.identitycenter} action={<ActionForm action={enableInstance} submit="Enable" testId="enable-identity-center" />}>
          Not enabled in this Region
        </Empty>
      </Page>
    );
  }
  const inst = found.value;
  const { store, arn } = inst;

  if (tab === "groups") {
    const groups = await load(async () => {
      const list = await listGroups(store);
      return Promise.all(list.map(async (g) => ({ g, members: (await memberships(store, g.GroupId!)).length })));
    });
    const taken = groups.ok ? groups.value.map(({ g }) => g.DisplayName!).filter(Boolean) : [];
    const create = (
      <Sheet title="Create group" label="Create group" testId="create-sso-group">
        <ActionForm action={createGroup.bind(null, store)} submit="Create group" testId="create-sso-group">
          <Field label="Group name" rule={GROUP_NAME} member="DisplayName" taken={taken} unique>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Description" rule={CreateGroup.Description} member="Description">
            <input name="description" />
          </Field>
        </ActionForm>
      </Sheet>
    );
    return (
      <Page
        title={title}
        actions={
          <>
            <Links />
            {create}
          </>
        }
      >
        {groups.ok ? (
          <List
            label="Groups"
            empty={<Empty icon={ICONS.users} action={create} />}
            rows={groups.value.map(({ g, members }) => ({
              key: g.GroupId!,
              icon: <AwsIcon icon={ICONS.users} size={22} />,
              title: g.DisplayName,
              subtitle: g.Description,
              href: `/identitycenter/groups/${g.GroupId}`,
              meta: (
                <Pill icon={<Users size={11} />} title="Members">
                  {members}
                </Pill>
              ),
              actions: (
                <ActionForm action={deleteGroup.bind(null, store, g.GroupId!, arn, false)} submit={`Delete ${g.DisplayName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${g.DisplayName}? Its assignments are removed.`} />
              ),
            }))}
          />
        ) : (
          <ErrorNotice error={groups.error} />
        )}
      </Page>
    );
  }

  if (tab === "permissionsets") {
    if (!inst.permissionSets) {
      return (
        <Page title={title} actions={<Links />}>
          <Empty icon={ICONS.policy} action={<ActionForm action={enablePermissionSets.bind(null, arn)} submit="Enable permission sets" testId="enable-permission-sets" />}>
            Permission sets are off for this account instance
          </Empty>
        </Page>
      );
    }
    const sets = await load(async () => {
      const list = await permissionSets(arn);
      const c = await ssoAdmin();
      return Promise.all(
        list.map(async (p) => ({
          p,
          stale: await outdated(arn, p.PermissionSetArn!).catch(() => []),
          policies: await all(
            (NextToken) => c.send(new ListManagedPoliciesInPermissionSetCommand({ InstanceArn: arn, PermissionSetArn: p.PermissionSetArn, NextToken })),
            (r) => r.AttachedManagedPolicies,
            (r) => r.NextToken,
          ),
        })),
      );
    });
    const taken = sets.ok ? sets.value.map(({ p }) => p.Name!).filter(Boolean) : [];
    const create = (
      <Sheet title="Create permission set" label="Create permission set" testId="create-permission-set">
        <ActionForm action={createPermissionSet.bind(null, arn)} submit="Create" testId="create-permission-set">
          <Field label="Name" rule={PERMISSION_SET_NAME} member="Name" taken={taken} unique>
            <input name="name" required autoFocus />
          </Field>
          <Field label="Description" rule={CreatePermissionSet.Description} member="Description">
            <input name="description" />
          </Field>
          <Field label="AWS managed policy">
            <select name="policy" defaultValue={POLICIES[2]}>
              <option value="">None</option>
              {POLICIES.map((p) => (
                <option key={p} value={p}>
                  {p.split("/").pop()}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Session duration (hours)" rule={HOURS}>
            <input name="hours" type="number" min={1} max={12} defaultValue={1} />
          </Field>
          <Field label="Relay state" rule={CreatePermissionSet.RelayState} member="RelayState" format="url">
            <input name="relay" placeholder="https://console.aws.amazon.com/s3" />
          </Field>
        </ActionForm>
      </Sheet>
    );
    return (
      <Page
        title={title}
        actions={
          <>
            <Links />
            {create}
          </>
        }
      >
        {sets.ok ? (
          <List
            label="Permission sets"
            empty={<Empty icon={ICONS.policy} action={create} />}
            rows={sets.value.map(({ p, stale, policies }) => ({
              key: p.PermissionSetArn!,
              icon: <AwsIcon icon={ICONS.policy} size={22} />,
              title: p.Name,
              subtitle: policies.map((x) => x.Name).join(", ") || p.Description,
              href: `/identitycenter/permissionset?arn=${encodeURIComponent(p.PermissionSetArn!)}`,
              meta: (
                <>
                  {stale.length > 0 && (
                    <Pill tone="warn" icon={<RefreshCw size={11} />} title="Accounts with an older version">
                      {stale.length} outdated
                    </Pill>
                  )}
                  <Pill icon={<Timer size={11} />} title="Session duration">
                    {duration(p.SessionDuration)}
                  </Pill>
                </>
              ),
              actions: (
                <>
                  {stale.length > 0 && <ActionForm action={provisionPermissionSet.bind(null, arn, p.PermissionSetArn!)} submit={`Provision ${p.Name}`} icon={<RefreshCw size={15} />} />}
                  <ActionForm action={deletePermissionSet.bind(null, arn, p.PermissionSetArn!, false)} submit={`Delete ${p.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p.Name}?`} />
                </>
              ),
            }))}
          />
        ) : (
          <ErrorNotice error={sets.error} />
        )}
      </Page>
    );
  }

  const users = await load(() => listUsers(store));
  const taken = users.ok ? users.value.map((u) => u.UserName!).filter(Boolean) : [];
  const create = (
    <Sheet title="Add user" label="Add user" testId="create-sso-user">
      <ActionForm action={createUser.bind(null, store)} submit="Add user" testId="create-sso-user">
        <Field label="Username" rule={USERNAME} member="UserName" taken={taken} unique>
          <input name="username" required autoFocus />
        </Field>
        <div className="form-row">
          <Field label="First name" rule={CreateUser.Name.fields?.GivenName} member="Name.GivenName">
            <input name="given" required />
          </Field>
          <Field label="Last name" rule={CreateUser.Name.fields?.FamilyName} member="Name.FamilyName">
            <input name="family" required />
          </Field>
        </div>
        <Field label="Email address" rule={CreateUser.Emails.item?.fields?.Value} member="Emails.Value" format="email">
          <input name="email" type="email" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page
      title={title}
      actions={
        <>
          <Links />
          {create}
        </>
      }
    >
      <Facts
        items={[
          [
            "AWS access portal URL",
            <span key="u" style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
              <code>{inst.startUrl}</code>
              <CopyButton value={inst.startUrl} label="Copy start URL" />
            </span>,
          ],
          ["Region", inst.region],
        ]}
      />
      {users.ok ? (
        <List
          label="Users"
          empty={<Empty icon={ICONS.user} action={create} />}
          rows={users.value.map((u) => ({
            key: u.UserId!,
            icon: <AwsIcon icon={ICONS.user} size={22} />,
            title: u.UserName,
            subtitle: [userName(u) !== u.UserName && userName(u), u.Emails?.find((e) => e.Primary)?.Value ?? u.Emails?.[0]?.Value].filter(Boolean).join(" · "),
            href: `/identitycenter/users/${u.UserId}`,
            meta: u.UserStatus === "DISABLED" ? <Pill tone="warn">disabled</Pill> : undefined,
            actions: (
              <ActionForm action={deleteUser.bind(null, store, u.UserId!, arn, false)} submit={`Delete ${u.UserName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${u.UserName}? Their assignments are removed.`} />
            ),
          }))}
        />
      ) : (
        <ErrorNotice error={users.error} />
      )}
    </Page>
  );
}
