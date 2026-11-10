import "server-only";

import { DescribeParametersCommand, GetParameterCommand, GetParametersCommand, type ParameterMetadata } from "@aws-sdk/client-ssm";
import { KMSClient, ListAliasesCommand } from "@aws-sdk/client-kms";
import { all, client } from "@mws-dashboard/aws";

import { ssm } from "./clients";

export type Listed = { meta: ParameterMetadata; value?: string; error?: string };

export async function listParameters(prefix = "", decrypt = false, values = true): Promise<Listed[]> {
  const c = await ssm();
  const list = await all(
    (NextToken) =>
      c.send(
        new DescribeParametersCommand({
          NextToken,
          MaxResults: 50,
          ...(prefix ? { ParameterFilters: [{ Key: "Name", Option: "BeginsWith", Values: [prefix] }] } : {}),
        }),
      ),
    (r) => r.Parameters,
    (r) => r.NextToken,
  );
  const found = new Map<string, string>();
  const failed = new Map<string, string>();
  if (values) {
    const names = list.map((p) => p.Name!);
    const chunks = Array.from({ length: Math.ceil(names.length / 10) }, (_, i) => names.slice(i * 10, i * 10 + 10));
    await Promise.all(
      chunks.map(async (Names) => {
        try {
          const out = await c.send(new GetParametersCommand({ Names, WithDecryption: decrypt }));
          for (const p of out.Parameters ?? []) found.set(p.Name!, p.Value ?? "");
        } catch (e) {
          // One SecureString the caller may not decrypt fails the whole
          // batch: read those ten one by one, so only that row is masked.
          if (!decrypt) throw e;
          await Promise.all(
            Names.map((Name) =>
              c.send(new GetParameterCommand({ Name, WithDecryption: true })).then(
                (r) => found.set(Name, r.Parameter?.Value ?? ""),
                (err: Error) => failed.set(Name, err.name),
              ),
            ),
          );
        }
      }),
    );
  }
  return list.map((p) => ({ meta: p, value: found.get(p.Name!), error: failed.get(p.Name!) }));
}

/** KMS aliases, for a SecureString's key (a failed lookup only loses suggestions). */
export async function kmsAliases() {
  try {
    const kms = await client(KMSClient);
    const aliases = await all((Marker) => kms.send(new ListAliasesCommand({ Marker })), (r) => r.Aliases, (r) => (r.Truncated ? r.NextMarker : undefined));
    return aliases.filter((a) => a.TargetKeyId || a.AliasName === "alias/aws/ssm").map((a) => a.AliasName!);
  } catch {
    return ["alias/aws/ssm"];
  }
}

/** The folder a parameter sits in, for links back to the browser. */
export const folderOf = (name: string) => name.slice(0, name.lastIndexOf("/") + 1);

/** A parameter's policies as the JSON array PutParameter takes. */
export function policyJson(policies: { PolicyText?: string }[] | undefined) {
  if (!policies?.length) return undefined;
  return JSON.stringify(policies.map((p) => JSON.parse(p.PolicyText ?? "{}")));
}
