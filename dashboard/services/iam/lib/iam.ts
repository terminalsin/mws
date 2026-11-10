import "server-only";

import {
  ListAttachedGroupPoliciesCommand,
  ListAttachedRolePoliciesCommand,
  ListAttachedUserPoliciesCommand,
  ListEntitiesForPolicyCommand,
  ListGroupPoliciesCommand,
  ListGroupsCommand,
  ListGroupsForUserCommand,
  ListInstanceProfilesForRoleCommand,
  ListPoliciesCommand,
  ListPolicyVersionsCommand,
  ListRolePoliciesCommand,
  ListUserPoliciesCommand,
  GetGroupCommand,
  type AttachedPolicy,
  type IAMClient,
  type PolicyScopeType,
} from "@aws-sdk/client-iam";
import { all, FieldError } from "@mws-dashboard/aws";

export type Kind = "role" | "user" | "group";

/** IAM pages with `Marker`, ending when `IsTruncated` is false. */
const next = (r: { IsTruncated?: boolean; Marker?: string }) => (r.IsTruncated ? r.Marker : undefined);

/** Every managed policy attached to a role, user or group. */
export function attachedPolicies(client: IAMClient, kind: Kind, name: string): Promise<AttachedPolicy[]> {
  if (kind === "role") return all((Marker) => client.send(new ListAttachedRolePoliciesCommand({ RoleName: name, Marker })), (r) => r.AttachedPolicies, next);
  if (kind === "user") return all((Marker) => client.send(new ListAttachedUserPoliciesCommand({ UserName: name, Marker })), (r) => r.AttachedPolicies, next);
  return all((Marker) => client.send(new ListAttachedGroupPoliciesCommand({ GroupName: name, Marker })), (r) => r.AttachedPolicies, next);
}

/** The names of every inline policy of a role, user or group. */
export function inlinePolicies(client: IAMClient, kind: Kind, name: string): Promise<string[]> {
  if (kind === "role") return all((Marker) => client.send(new ListRolePoliciesCommand({ RoleName: name, Marker })), (r) => r.PolicyNames, next);
  if (kind === "user") return all((Marker) => client.send(new ListUserPoliciesCommand({ UserName: name, Marker })), (r) => r.PolicyNames, next);
  return all((Marker) => client.send(new ListGroupPoliciesCommand({ GroupName: name, Marker })), (r) => r.PolicyNames, next);
}

export const groupsForUser = (client: IAMClient, user: string) =>
  all((Marker) => client.send(new ListGroupsForUserCommand({ UserName: user, Marker })), (r) => r.Groups, next);

export const allGroups = (client: IAMClient) => all((Marker) => client.send(new ListGroupsCommand({ Marker })), (r) => r.Groups, next);

export const groupMembers = (client: IAMClient, group: string) =>
  all((Marker) => client.send(new GetGroupCommand({ GroupName: group, Marker })), (r) => r.Users, next);

export const instanceProfilesForRole = (client: IAMClient, role: string) =>
  all((Marker) => client.send(new ListInstanceProfilesForRoleCommand({ RoleName: role, Marker })), (r) => r.InstanceProfiles, next);

export const policies = (client: IAMClient, Scope: PolicyScopeType = "All") =>
  all((Marker) => client.send(new ListPoliciesCommand({ Scope, Marker, MaxItems: 1000 })), (r) => r.Policies, next);

export const policyVersions = (client: IAMClient, arn: string) =>
  all((Marker) => client.send(new ListPolicyVersionsCommand({ PolicyArn: arn, Marker })), (r) => r.Versions, next);

/** Every role, user and group a managed policy is attached to. */
export async function policyEntities(client: IAMClient, arn: string) {
  const pages = await all(
    (Marker) => client.send(new ListEntitiesForPolicyCommand({ PolicyArn: arn, Marker })),
    (r) => [r],
    next,
  );
  return {
    roles: pages.flatMap((p) => p.PolicyRoles ?? []),
    users: pages.flatMap((p) => p.PolicyUsers ?? []),
    groups: pages.flatMap((p) => p.PolicyGroups ?? []),
  };
}

/** `key=value` lines as IAM tags; a line without `=` lands on the field. */
export function parseTags(value: string, field = "tags") {
  return value
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i) => {
      const [Key, ...rest] = l.split("=");
      if (!rest.length || !Key.trim()) throw new FieldError(field, `Line ${i + 1}: key=value`, "format");
      return { Key: Key.trim(), Value: rest.join("=").trim() };
    });
}

/** Service-linked roles belong to the service: AWS deletes them through
 * DeleteServiceLinkedRole, which checks the service no longer uses them. */
export const serviceLinked = (path: string | undefined) => !!path?.startsWith("/aws-service-role/");
