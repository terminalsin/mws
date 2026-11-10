import "server-only";

import { type InventoryItem } from "@mws-dashboard/aws";

import { groups, instance, permissionSets, users, userName } from "./sso";

/** Identity Center's users, groups and permission sets. */
export async function directory(): Promise<InventoryItem[]> {
  const i = await instance();
  if (!i) return [];
  const [u, g, p] = await Promise.all([users(i.store), groups(i.store), i.permissionSets ? permissionSets(i.arn) : []]);
  return [
    ...u.map((x) => ({
      service: "identitycenter",
      type: "Identity Center user",
      id: `identitycenter:user:${x.UserId}`,
      name: x.UserName!,
      href: `/identitycenter/users/${x.UserId}`,
      detail: userName(x) !== x.UserName ? userName(x) : x.Emails?.[0]?.Value,
    })),
    ...g.map((x) => ({
      service: "identitycenter",
      type: "Identity Center group",
      id: `identitycenter:group:${x.GroupId}`,
      name: x.DisplayName!,
      href: `/identitycenter/groups/${x.GroupId}`,
      detail: x.Description,
    })),
    ...p.map((x) => ({
      service: "identitycenter",
      type: "Permission set",
      id: x.PermissionSetArn!,
      name: x.Name!,
      href: `/identitycenter/permissionset?arn=${encodeURIComponent(x.PermissionSetArn!)}`,
      detail: x.Description,
    })),
  ];
}
