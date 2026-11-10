import "server-only";

import { KMSClient, ListAliasesCommand, ListKeysCommand } from "@aws-sdk/client-kms";
import { LambdaClient, ListFunctionsCommand } from "@aws-sdk/client-lambda";
import { client, collect } from "@mws-dashboard/aws";

// What the forms' fields usually point at, so a mistyped key or function
// gets a "did you mean". A failed lookup only loses the suggestions.

const quietly = async (read: () => Promise<string[]>) => read().catch(() => [] as string[]);

/** KMS keys by alias (`alias/x`, as Secrets Manager accepts them) and id. */
export const kmsKeys = () =>
  quietly(async () => {
    const kms = await client(KMSClient);
    const [aliases, keys] = await Promise.all([
      collect((Marker) => kms.send(new ListAliasesCommand({ Marker })), (r) => r.Aliases, (r) => r.NextMarker),
      collect((Marker) => kms.send(new ListKeysCommand({ Marker })), (r) => r.Keys, (r) => r.NextMarker),
    ]);
    return [...aliases.map((a) => a.AliasName!), ...keys.map((k) => k.KeyId!)];
  });

/** Lambda function ARNs, for rotation. */
export const functionArns = () =>
  quietly(async () => {
    const lambda = await client(LambdaClient);
    const fns = await collect((Marker) => lambda.send(new ListFunctionsCommand({ Marker })), (r) => r.Functions, (r) => r.NextMarker);
    return fns.map((f) => f.FunctionArn!);
  });
