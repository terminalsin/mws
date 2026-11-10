import { ListGroupsCommand, ListUsersCommand } from "@aws-sdk/client-identitystore";
import { DescribePermissionSetCommand, ListInstancesCommand, ListManagedPoliciesInPermissionSetCommand, ListPermissionSetsCommand } from "@aws-sdk/client-sso-admin";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Page, Pill, Sheet, type Rule } from "@mws-dashboard/ui";
import { CreateGroup, CreateUser } from "@mws-dashboard/ui/model/identitystore";
import { CreatePermissionSet } from "@mws-dashboard/ui/model/sso-admin";
import { Timer, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, identitystore, ssoAdmin } from "../../lib/clients";
import { createGroup, createPermissionSet, createUser, deleteGroup, deletePermissionSet, deleteUser, enableInstance } from "./actions";

export const metadata: Metadata = { title: "IAM Identity Center" };

type Props = { searchParams: Promise<{ tab?: string }> };

// The identity store's patterns allow any visible character; spell out what
// they reject. It compares user and group names ignoring case.
const USERNAME: Rule = { ...CreateUser.UserName, hint: "No spaces", takenIgnoreCase: true };
const PERMISSION_SET_NAME: Rule = { ...CreatePermissionSet.Name, hint: "Letters, digits and +=,.@-_", generate: "name" };
const GROUP_NAME: Rule = { ...CreateGroup.DisplayName, generate: "name", takenIgnoreCase: true };

const POLICIES = ["arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/PowerUserAccess", "arn:aws:iam::aws:policy/ReadOnlyAccess", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess", "arn:aws:iam::aws:policy/job-function/Billing"];

export default async function IdentityCenter({ searchParams }: Props) {
  const { tab = "users" } = await searchParams;
  const instance = await load(async () => (await (await ssoAdmin()).send(new ListInstancesCommand({}))).Instances?.[0]);
  if (!instance.ok) {
    return (
      <Page title="IAM Identity Center">
        <ErrorNotice error={instance.error} />
      </Page>
    );
  }
  if (!instance.value) {
    return (
      <Page title="IAM Identity Center">
        <Empty icon={ICONS.identitycenter} action={<ActionForm action={enableInstance} submit="Enable" testId="enable-identity-center" />} />
      </Page>
    );
  }
  const store = instance.value.IdentityStoreId!;
  const arn = instance.value.InstanceArn!;
  if (tab === "groups") {
    const groups = await load(async () => (await (await identitystore()).send(new ListGroupsCommand({ IdentityStoreId: store }))).Groups ?? []);
    const taken = groups.ok ? groups.value.map((g) => g.DisplayName!).filter(Boolean) : [];
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
      <Page title="Groups" actions={create}>
        {groups.ok ? (
          <List
            label="Groups"
            empty={<Empty icon={ICONS.users} action={create} />}
            rows={groups.value.map((g) => ({
              key: g.GroupId!,
              icon: <AwsIcon icon={ICONS.users} size={22} />,
              title: g.DisplayName,
              subtitle: g.Description,
              actions: <ActionForm action={deleteGroup.bind(null, store, g.GroupId!)} submit={`Delete ${g.DisplayName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${g.DisplayName}?`} />,
            }))}
          />
        ) : (
          <ErrorNotice error={groups.error} />
        )}
      </Page>
    );
  }
  if (tab === "permissionsets") {
    const sets = await load(async () => {
      const client = await ssoAdmin();
      const arns = (await client.send(new ListPermissionSetsCommand({ InstanceArn: arn }))).PermissionSets ?? [];
      return Promise.all(
        arns.map(async (p) => ({
          p: (await client.send(new DescribePermissionSetCommand({ InstanceArn: arn, PermissionSetArn: p }))).PermissionSet!,
          policies: (await client.send(new ListManagedPoliciesInPermissionSetCommand({ InstanceArn: arn, PermissionSetArn: p }))).AttachedManagedPolicies ?? [],
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
          <Field label="Session duration (hours)">
            <input name="hours" type="number" min={1} max={12} defaultValue={1} />
          </Field>
        </ActionForm>
      </Sheet>
    );
    return (
      <Page title="Permission sets" actions={create}>
        {sets.ok ? (
          <List
            label="Permission sets"
            empty={<Empty icon={ICONS.policy} action={create} />}
            rows={sets.value.map(({ p, policies }) => ({
              key: p.PermissionSetArn!,
              icon: <AwsIcon icon={ICONS.policy} size={22} />,
              title: p.Name,
              subtitle: policies.map((x) => x.Name).join(", ") || p.Description,
              meta: (
                <Pill icon={<Timer size={11} />} title="Session duration">
                  {p.SessionDuration?.replace(/^PT/, "").toLowerCase()}
                </Pill>
              ),
              actions: <ActionForm action={deletePermissionSet.bind(null, arn, p.PermissionSetArn!)} submit={`Delete ${p.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${p.Name}?`} />,
            }))}
          />
        ) : (
          <ErrorNotice error={sets.error} />
        )}
      </Page>
    );
  }
  const users = await load(async () => (await (await identitystore()).send(new ListUsersCommand({ IdentityStoreId: store }))).Users ?? []);
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
    <Page title="Users" actions={create}>
      {users.ok ? (
        <List
          label="Users"
          empty={<Empty icon={ICONS.user} action={create} />}
          rows={users.value.map((u) => ({
            key: u.UserId!,
            icon: <AwsIcon icon={ICONS.user} size={22} />,
            title: u.DisplayName ?? u.UserName,
            subtitle: u.Emails?.[0]?.Value ?? u.UserName,
            actions: <ActionForm action={deleteUser.bind(null, store, u.UserId!)} submit={`Delete ${u.UserName}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${u.UserName}?`} />,
          }))}
        />
      ) : (
        <ErrorNotice error={users.error} />
      )}
    </Page>
  );
}
