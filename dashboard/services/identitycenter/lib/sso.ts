import "server-only";

import { ListGroupMembershipsCommand, ListGroupsCommand, ListUsersCommand, type Group, type User } from "@aws-sdk/client-identitystore";
import { ListAccountsCommand, type Account } from "@aws-sdk/client-organizations";
import {
  DescribeInstanceCommand,
  DescribePermissionSetCommand,
  ListAccountAssignmentsForPrincipalCommand,
  ListAccountAssignmentsCommand,
  ListAccountsForProvisionedPermissionSetCommand,
  ListInstancesCommand,
  ListPermissionSetsCommand,
  type PermissionSet,
  type PrincipalType,
} from "@aws-sdk/client-sso-admin";
import { all, client, region } from "@mws-dashboard/aws";
import { OrganizationsClient } from "@aws-sdk/client-organizations";

import { identitystore, ssoAdmin } from "./clients";

/** The Identity Center instance this account sees in the selected Region,
 * with what DescribeInstance adds (status, owner, whether permission sets
 * are on), or null when none is enabled. */
export async function instance() {
  const admin = await ssoAdmin();
  const first = (await all((NextToken) => admin.send(new ListInstancesCommand({ NextToken })), (r) => r.Instances, (r) => r.NextToken))[0];
  if (!first) return null;
  const d = await admin.send(new DescribeInstanceCommand({ InstanceArn: first.InstanceArn }));
  return {
    arn: first.InstanceArn!,
    store: first.IdentityStoreId!,
    name: d.Name ?? first.Name,
    owner: d.OwnerAccountId ?? first.OwnerAccountId,
    status: d.Status ?? first.Status,
    created: d.CreatedDate ?? first.CreatedDate,
    permissionSets: d.PermissionSetsEnabled !== false,
    region: await region(),
    /** The AWS access portal: what `aws configure sso` asks for. */
    startUrl: `https://${first.IdentityStoreId}.awsapps.com/start`,
  };
}

export type Instance = NonNullable<Awaited<ReturnType<typeof instance>>>;

export async function users(store: string): Promise<User[]> {
  const c = await identitystore();
  return all((NextToken) => c.send(new ListUsersCommand({ IdentityStoreId: store, NextToken })), (r) => r.Users, (r) => r.NextToken);
}

export async function groups(store: string): Promise<Group[]> {
  const c = await identitystore();
  return all((NextToken) => c.send(new ListGroupsCommand({ IdentityStoreId: store, NextToken })), (r) => r.Groups, (r) => r.NextToken);
}

export async function memberships(store: string, group: string) {
  const c = await identitystore();
  return all((NextToken) => c.send(new ListGroupMembershipsCommand({ IdentityStoreId: store, GroupId: group, NextToken })), (r) => r.GroupMemberships, (r) => r.NextToken);
}

/** Every permission set of the instance, described. */
export async function permissionSets(instanceArn: string): Promise<PermissionSet[]> {
  const c = await ssoAdmin();
  const arns = await all((NextToken) => c.send(new ListPermissionSetsCommand({ InstanceArn: instanceArn, NextToken })), (r) => r.PermissionSets, (r) => r.NextToken);
  return Promise.all(arns.map(async (p) => (await c.send(new DescribePermissionSetCommand({ InstanceArn: instanceArn, PermissionSetArn: p }))).PermissionSet!));
}

/** Accounts where a permission set's roles are older than the set. */
export async function outdated(instanceArn: string, set: string) {
  const c = await ssoAdmin();
  return all(
    (NextToken) =>
      c.send(new ListAccountsForProvisionedPermissionSetCommand({ InstanceArn: instanceArn, PermissionSetArn: set, ProvisioningStatus: "LATEST_PERMISSION_SET_NOT_PROVISIONED", NextToken })),
    (r) => r.AccountIds,
    (r) => r.NextToken,
  );
}

export async function provisionedAccounts(instanceArn: string, set: string) {
  const c = await ssoAdmin();
  return all(
    (NextToken) => c.send(new ListAccountsForProvisionedPermissionSetCommand({ InstanceArn: instanceArn, PermissionSetArn: set, NextToken })),
    (r) => r.AccountIds,
    (r) => r.NextToken,
  );
}

/** The accounts assignments can target: the organization's, or only the
 * instance's own account when it is not in one (an account instance). */
export async function accounts(owner: string | undefined): Promise<Account[]> {
  try {
    const orgs = await client(OrganizationsClient);
    return await all((NextToken) => orgs.send(new ListAccountsCommand({ NextToken })), (r) => r.Accounts, (r) => r.NextToken);
  } catch (e) {
    const name = (e as { name?: string }).name ?? "";
    if (!/AWSOrganizationsNotInUse|AccessDenied/.test(name)) throw e;
    return owner ? [{ Id: owner, Name: "This account" }] : [];
  }
}

export async function assignmentsForPrincipal(instanceArn: string, id: string, type: PrincipalType) {
  const c = await ssoAdmin();
  return all(
    (NextToken) => c.send(new ListAccountAssignmentsForPrincipalCommand({ InstanceArn: instanceArn, PrincipalId: id, PrincipalType: type, NextToken })),
    (r) => r.AccountAssignments,
    (r) => r.NextToken,
  );
}

export async function assignmentsInAccount(instanceArn: string, account: string, set: string) {
  const c = await ssoAdmin();
  return all(
    (NextToken) => c.send(new ListAccountAssignmentsCommand({ InstanceArn: instanceArn, AccountId: account, PermissionSetArn: set, NextToken })),
    (r) => r.AccountAssignments,
    (r) => r.NextToken,
  );
}

/** "PT8H" as "8h", "PT1H30M" as "1h30m". */
export const duration = (iso: string | undefined) => iso?.replace(/^PT/, "").toLowerCase();

/** The id at the end of a permission set ARN (for its role name and URL). */
export const setId = (arn: string) => arn.split("/").pop()!;

export const userName = (u: User) => u.DisplayName || [u.Name?.GivenName, u.Name?.FamilyName].filter(Boolean).join(" ") || u.UserName || u.UserId!;
