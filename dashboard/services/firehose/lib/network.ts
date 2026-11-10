import "server-only";

import { ListFunctionsCommand, LambdaClient } from "@aws-sdk/client-lambda";
import { ListRolesCommand } from "@aws-sdk/client-iam";
import { ListStreamsCommand } from "@aws-sdk/client-kinesis";
import { all, client } from "@mws-dashboard/aws";

import { iam, kinesis } from "./clients";

/** Roles whose trust policy names `service` as a principal, for the role pickers. */
export async function rolesTrusting(service: string) {
  const c = await iam();
  const roles = await all(
    (Marker) => c.send(new ListRolesCommand({ Marker })),
    (r) => r.Roles,
    (r) => (r.IsTruncated ? r.Marker : undefined),
  );
  return roles.filter((r) => {
    try {
      const doc = JSON.parse(
        decodeURIComponent(r.AssumeRolePolicyDocument ?? "{}"),
      ) as {
        Statement?:
          | { Principal?: { Service?: string | string[] } }[]
          | { Principal?: { Service?: string | string[] } };
      };
      const statements = Array.isArray(doc.Statement)
        ? doc.Statement
        : doc.Statement
          ? [doc.Statement]
          : [];
      return statements.some((s) =>
        [s.Principal?.Service ?? []].flat().includes(service),
      );
    } catch {
      return false;
    }
  });
}

/** Every Kinesis stream ARN, for the source picker. */
export async function kinesisArns() {
  const c = await kinesis();
  return all(
    (NextToken) => c.send(new ListStreamsCommand({ NextToken })),
    (r) => r.StreamSummaries?.map((s) => s.StreamARN!),
    (r) => (r.HasMoreStreams ? r.NextToken : undefined),
  );
}

/** Every Lambda function ARN, for the transform picker. */
export async function functionArns() {
  const c = await client(LambdaClient);
  return all(
    (Marker) => c.send(new ListFunctionsCommand({ Marker })),
    (r) => r.Functions?.map((f) => f.FunctionArn!),
    (r) => r.NextMarker,
  );
}
