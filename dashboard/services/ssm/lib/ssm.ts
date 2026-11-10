import "server-only";

import { DescribeParametersCommand, GetParametersCommand } from "@aws-sdk/client-ssm";
import { collect } from "@mws-dashboard/aws";

import { ssm } from "./clients";

export async function listParameters(prefix = "", decrypt = false, values = true) {
  const client = await ssm();
  const list = await collect(
    (NextToken) =>
      client.send(
        new DescribeParametersCommand({
          NextToken,
          MaxResults: 50,
          ...(prefix ? { ParameterFilters: [{ Key: "Name", Option: "BeginsWith", Values: [prefix] }] } : {}),
        }),
      ),
    (r) => r.Parameters,
    (r) => r.NextToken,
    5000,
  );
  const found = new Map<string, string>();
  if (values) {
    const names = list.map((p) => p.Name!);
    const chunks = Array.from({ length: Math.ceil(names.length / 10) }, (_, i) => names.slice(i * 10, i * 10 + 10));
    const outs = await Promise.all(chunks.map((Names) => client.send(new GetParametersCommand({ Names, WithDecryption: decrypt }))));
    for (const out of outs) for (const p of out.Parameters ?? []) found.set(p.Name!, p.Value ?? "");
  }
  return list.map((p) => ({ meta: p, value: found.get(p.Name!) }));
}
