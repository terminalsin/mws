import "server-only";

import { ListGroupsCommand, ListInstanceProfilesCommand, ListPoliciesCommand, ListRolesCommand, ListUsersCommand } from "@aws-sdk/client-iam";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { iam } from "./clients";

const next = (r: { IsTruncated?: boolean; Marker?: string }) => (r.IsTruncated ? r.Marker : undefined);

export async function principals(): Promise<InventoryItem[]> {
  const client = await iam();
  const [users, roles, groups, policies, profiles] = await Promise.all([
    all((Marker) => client.send(new ListUsersCommand({ Marker })), (r) => r.Users, next),
    all((Marker) => client.send(new ListRolesCommand({ Marker })), (r) => r.Roles, next),
    all((Marker) => client.send(new ListGroupsCommand({ Marker })), (r) => r.Groups, next),
    all((Marker) => client.send(new ListPoliciesCommand({ Marker, Scope: "Local" })), (r) => r.Policies, next),
    all((Marker) => client.send(new ListInstanceProfilesCommand({ Marker })), (r) => r.InstanceProfiles, next),
  ]);
  return [
    ...users.map((u) => ({
      service: "iam",
      type: "User",
      id: u.Arn!,
      name: u.UserName!,
      href: `/iam/users/${encodeURIComponent(u.UserName!)}`,
    })),
    // Service-linked roles are AWS's, not the account's.
    ...roles
      .filter((r) => !r.Path?.startsWith("/aws-service-role/"))
      .map((r) => ({
        service: "iam",
        type: "Role",
        id: r.Arn!,
        name: r.RoleName!,
        href: `/iam/roles/${encodeURIComponent(r.RoleName!)}`,
        detail: r.Description,
      })),
    ...groups.map((g) => ({
      service: "iam",
      type: "Group",
      id: g.Arn!,
      name: g.GroupName!,
      href: `/iam/groups/${encodeURIComponent(g.GroupName!)}`,
    })),
    ...policies.map((p) => ({
      service: "iam",
      type: "Policy",
      id: p.Arn!,
      name: p.PolicyName!,
      href: `/iam/policy?arn=${encodeURIComponent(p.Arn!)}`,
      detail: p.Description,
    })),
    ...profiles.map((p) => ({
      service: "iam",
      type: "Instance profile",
      id: p.Arn!,
      name: p.InstanceProfileName!,
      href: `/iam/instance-profiles/${encodeURIComponent(p.InstanceProfileName!)}`,
      detail: p.Roles?.[0]?.RoleName,
    })),
  ];
}
