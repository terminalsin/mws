import type { Rule } from "@mws-dashboard/ui";
import { CreateResourceShare } from "@mws-dashboard/ui/model/ram";

import type { shareTargets } from "./clients";

// The principals RAM accepts (its model leaves them unconstrained).
export const PRINCIPAL: Rule = {
  format: "principal",
  pattern:
    "^(\\d{12}|arn:aws[\\w-]*:organizations::\\d{12}:(organization/o-[a-z0-9]+|ou/o-[a-z0-9]+/ou-[a-z0-9-]+)|arn:aws[\\w-]*:iam::\\d{12}:(role|user)/.+|[a-z0-9.-]+\\.amazonaws\\.com)$",
  hint: "An account, organization, OU, IAM role or user, or service",
};

/** Lists checked item by item, with the account's CAs and organization
 * principals as suggestions. */
export const shareRules = (targets: Awaited<ReturnType<typeof shareTargets>> | null) =>
  ({
    resources: { ...CreateResourceShare.resourceArns, item: { type: "string", format: "arn", known: targets?.resources, arn: targets?.caArn } },
    principals: { ...CreateResourceShare.principals, item: { ...PRINCIPAL, known: targets?.principals } },
  }) satisfies Record<string, Rule>;
