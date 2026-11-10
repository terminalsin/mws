import "server-only";

import { IAMClient } from "@aws-sdk/client-iam";
import { client } from "@mws-dashboard/aws";
import { SERVICES } from "@mws-dashboard/ui";

export const iam = () => client(IAMClient);

export const ICONS = {
  role: "resource/AWSIdentityAccessManagementRole",
  user: "resource/User",
  users: "resource/Users",
  policy: "resource/AWSIdentityAccessManagementPermissions",
};

/** IAM returns policy documents URL-encoded. */
export function policyDocument(doc: string | undefined) {
  if (!doc) return undefined;
  try {
    return decodeURIComponent(doc);
  } catch {
    return doc;
  }
}

/** The catalog icon of a service principal ("lambda.amazonaws.com"). */
export function principalIcon(principal: string): string {
  const name = principal.split(".")[0];
  const aliases: Record<string, string> = {
    states: "events",
    "edgelambda": "lambda",
    monitoring: "cloudwatch",
    logs: "cloudwatch",
    elasticloadbalancing: "elb",
    "ecs-tasks": "ecs",
    "acm-pca": "acmpca",
    "elasticfilesystem": "efs",
    scheduler: "events",
    "sso": "identitycenter",
  };
  const id = aliases[name] ?? name;
  return SERVICES.find((s) => s.id === id || s.endpoints.includes(name))?.icon ?? ICONS.role;
}

export type TrustKind = "service" | "federated" | "cross-account" | "account";

/** Who may assume a role, read from its trust policy. */
export function trust(document: string | undefined, account: string | null) {
  const services = new Set<string>();
  let kind: TrustKind = "account";
  try {
    const doc = JSON.parse(document ?? "{}");
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
    for (const s of statements) {
      const p = s?.Principal ?? {};
      for (const svc of [p.Service ?? []].flat()) services.add(svc);
      if (p.Federated) kind = "federated";
      for (const a of [p.AWS ?? []].flat() as string[]) {
        const acct = /^\d{12}$/.test(a) ? a : a.split(":")[4];
        if (acct && account && acct !== account && kind !== "federated") kind = "cross-account";
      }
    }
  } catch {
    // unreadable policy: treat as an account role
  }
  if (services.size && kind === "account") kind = "service";
  return { kind, services: [...services] };
}
