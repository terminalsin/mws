import "server-only";

import { ListRolesCommand, ListUsersCommand } from "@aws-sdk/client-iam";
import { collect, type InventoryItem } from "@mws-dashboard/aws";

import { iam } from "./clients";

export async function principals(): Promise<InventoryItem[]> {
  const client = await iam();
  const [users, roles] = await Promise.all([
    collect((Marker) => client.send(new ListUsersCommand({ Marker })), (r) => r.Users, (r) => (r.IsTruncated ? r.Marker : undefined)),
    collect((Marker) => client.send(new ListRolesCommand({ Marker })), (r) => r.Roles, (r) => (r.IsTruncated ? r.Marker : undefined)),
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
  ];
}
