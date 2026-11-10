import "server-only";

import { ListSecretsCommand } from "@aws-sdk/client-secrets-manager";
import { collect } from "@mws-dashboard/aws";

import { secrets } from "./clients";

export async function listSecrets() {
  const client = await secrets();
  return collect(
    (NextToken) => client.send(new ListSecretsCommand({ NextToken, IncludePlannedDeletion: true, MaxResults: 100 })),
    (r) => r.SecretList,
    (r) => r.NextToken,
  );
}

/** Secrets group by what they unlock; names and tags tell. */
export const SECRET_KINDS = [
  { id: "database", title: "Databases", prototype: "database db rds postgres mysql aurora redis password", rule: /\b(db|rds|database|postgres|mysql|aurora|redis|mongo|sql)\b/i },
  { id: "api", title: "API keys", prototype: "api key token oauth client secret stripe github slack", rule: /(api|token|oauth|webhook|stripe|github|slack|client.?secret)/i },
  { id: "certs", title: "Certificates", prototype: "certificate tls ssl private key pem", rule: /(cert|tls|ssl|pem|private.?key)/i },
  { id: "credentials", title: "Credentials", prototype: "credentials user password login access key", rule: /(cred|password|login|access.?key|user)/i },
];
