import "server-only";

import { ListRolesCommand } from "@aws-sdk/client-iam";
import { ListFunctionsCommand, ListTagsCommand } from "@aws-sdk/client-lambda";
import { collect } from "@mws-dashboard/aws";

import { iam, lambda } from "./clients";

/** Roles Lambda can assume (their trust policy names lambda.amazonaws.com). */
export async function lambdaRoles() {
  const client = await iam();
  const roles = await collect((Marker) => client.send(new ListRolesCommand({ Marker })), (r) => r.Roles, (r) => (r.IsTruncated ? r.Marker : undefined));
  return roles.filter((r) => decodeURIComponent(r.AssumeRolePolicyDocument ?? "").includes("lambda.amazonaws.com"));
}

export async function listFunctions() {
  const client = await lambda();
  const fns = await collect(
    (Marker) => client.send(new ListFunctionsCommand({ Marker })),
    (r) => r.Functions,
    (r) => r.NextMarker,
  );
  const tags = await Promise.all(fns.map((f) => client.send(new ListTagsCommand({ Resource: f.FunctionArn })).then((r) => r.Tags ?? {}, () => ({}))));
  return fns.map((f, i) => ({ ...f, tags: tags[i] as Record<string, string> }));
}
