import "server-only";

import { ListRolesCommand, ListUsersCommand } from "@aws-sdk/client-iam";
import { ago, collect, type InventoryItem } from "@mws-dashboard/aws";

import { iam } from "./clients";
import { listKeys } from "./kms";
import { listSecrets } from "./secrets";
import { listParameters } from "./ssm";

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
      href: `/security/iam/users/${encodeURIComponent(u.UserName!)}`,
    })),
    // Service-linked roles are AWS's, not the account's.
    ...roles
      .filter((r) => !r.Path?.startsWith("/aws-service-role/"))
      .map((r) => ({
        service: "iam",
        type: "Role",
        id: r.Arn!,
        name: r.RoleName!,
        href: `/security/iam/roles/${encodeURIComponent(r.RoleName!)}`,
        detail: r.Description,
      })),
  ];
}

export async function keys(): Promise<InventoryItem[]> {
  return (await listKeys())
    .filter((k) => k.meta.KeyManager === "CUSTOMER")
    .map(({ meta, aliases }) => ({
      service: "kms",
      type: "Key",
      id: meta.Arn!,
      name: aliases[0]?.replace(/^alias\//, "") ?? meta.KeyId!,
      href: `/security/kms/key?id=${meta.KeyId}`,
      detail: meta.KeySpec,
      signal: meta.KeyState === "PendingDeletion" ? { tone: "bad" as const, text: `Deletes ${ago(meta.DeletionDate)}` } : undefined,
    }));
}

export async function secretItems(): Promise<InventoryItem[]> {
  return (await listSecrets()).map((s) => ({
    service: "secretsmanager",
    type: "Secret",
    id: s.ARN!,
    name: s.Name!,
    href: `/security/secrets/secret?id=${encodeURIComponent(s.ARN!)}`,
    detail: s.Description,
    tags: Object.fromEntries((s.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""])),
    signal: s.DeletedDate ? { tone: "bad" as const, text: `Deletes ${ago(s.DeletedDate)}` } : undefined,
  }));
}

export async function parameters(): Promise<InventoryItem[]> {
  return (await listParameters("", false, false)).map(({ meta }) => ({
    service: "ssm",
    type: "Parameter",
    id: meta.ARN ?? meta.Name!,
    name: meta.Name!,
    href: `/security/ssm?path=${encodeURIComponent(meta.Name!.slice(0, meta.Name!.lastIndexOf("/") + 1))}`,
    detail: meta.Type,
  }));
}
