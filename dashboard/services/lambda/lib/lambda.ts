import "server-only";

import { ListFunctionsCommand, ListTagsCommand } from "@aws-sdk/client-lambda";
import { collect } from "@mws-dashboard/aws";

import { lambda } from "./clients";

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
