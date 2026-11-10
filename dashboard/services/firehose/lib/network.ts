import "server-only";

import { ListRolesCommand } from "@aws-sdk/client-iam";
import { collect } from "@mws-dashboard/aws";

import { iam } from "./clients";

/** Roles a service may assume, for the role pickers. */
export async function rolesTrusting(service: string) {
  const client = await iam();
  const roles = await collect(
    (Marker) => client.send(new ListRolesCommand({ Marker })),
    (r) => r.Roles,
    (r) => (r.IsTruncated ? r.Marker : undefined),
  );
  return roles.filter((r) => decodeURIComponent(r.AssumeRolePolicyDocument ?? "").includes(service));
}
