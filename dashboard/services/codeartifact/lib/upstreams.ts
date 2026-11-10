import "server-only";

import { DescribeRepositoryCommand, type RepositorySummary } from "@aws-sdk/client-codeartifact";

import { codeartifact } from "./clients";

/** Each repository's public upstream (by ARN), which is what tells
 * repositories apart at a glance; the summaries do not carry it. */
export async function publicUpstreams(repos: RepositorySummary[]): Promise<Map<string, string | undefined>> {
  const client = await codeartifact();
  return new Map(
    await Promise.all(
      repos.map((r) =>
        client
          .send(new DescribeRepositoryCommand({ domain: r.domainName, domainOwner: r.domainOwner, repository: r.name }))
          .then((d) => [r.arn!, d.repository?.externalConnections?.[0]?.externalConnectionName] as const, () => [r.arn!, undefined] as const),
      ),
    ),
  );
}
