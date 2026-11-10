import "server-only";

import {
  DescribeOrganizationCommand,
  ListAccountsForParentCommand,
  ListOrganizationalUnitsForParentCommand,
  ListPoliciesCommand,
  ListPoliciesForTargetCommand,
  ListRootsCommand,
  ListTargetsForPolicyCommand,
  type Account,
  type OrganizationsClient,
  type PolicySummary,
  type PolicyType,
} from "@aws-sdk/client-organizations";
import { all } from "@mws-dashboard/aws";

import { organizations } from "./clients";

export interface OrgNode {
  id: string;
  name: string;
  kind: "root" | "ou";
  accounts: Account[];
  children: OrgNode[];
  policies: PolicySummary[];
}

export const policiesForTarget = (client: OrganizationsClient, target: string, Filter: PolicyType = "SERVICE_CONTROL_POLICY") =>
  all((NextToken) => client.send(new ListPoliciesForTargetCommand({ TargetId: target, Filter, NextToken })), (r) => r.Policies, (r) => r.NextToken);

export const policiesOfType = (client: OrganizationsClient, Filter: PolicyType) =>
  all((NextToken) => client.send(new ListPoliciesCommand({ Filter, NextToken })), (r) => r.Policies, (r) => r.NextToken);

export const targetsForPolicy = (client: OrganizationsClient, id: string) =>
  all((NextToken) => client.send(new ListTargetsForPolicyCommand({ PolicyId: id, NextToken })), (r) => r.Targets, (r) => r.NextToken);

/** The whole organization as a tree: root, OUs and their accounts, with
 * the SCPs attached to each node. Every list is followed to its end. */
export async function orgTree() {
  const client = await organizations();
  const org = (await client.send(new DescribeOrganizationCommand({}))).Organization!;
  const root = (await all((NextToken) => client.send(new ListRootsCommand({ NextToken })), (r) => r.Roots, (r) => r.NextToken))[0];
  const scps = (target: string) => policiesForTarget(client, target).catch(() => []);
  async function node(id: string, name: string, kind: OrgNode["kind"]): Promise<OrgNode> {
    const [ous, accounts, policies] = await Promise.all([
      all((NextToken) => client.send(new ListOrganizationalUnitsForParentCommand({ ParentId: id, NextToken })), (r) => r.OrganizationalUnits, (r) => r.NextToken),
      all((NextToken) => client.send(new ListAccountsForParentCommand({ ParentId: id, NextToken })), (r) => r.Accounts, (r) => r.NextToken),
      scps(id),
    ]);
    return { id, name, kind, accounts, policies, children: await Promise.all(ous.map((o) => node(o.Id!, o.Name!, "ou"))) };
  }
  return { org, root, tree: await node(root.Id!, "Root", "root") };
}

export function flatten(n: OrgNode, depth = 0): { node: OrgNode; depth: number }[] {
  return [{ node: n, depth }, ...n.children.flatMap((c) => flatten(c, depth + 1))];
}

/** The policy types the console offers, AWS's tab names first. */
export const POLICY_TYPES: { type: PolicyType; label: string; short: string }[] = [
  { type: "SERVICE_CONTROL_POLICY", label: "Service control policies", short: "SCP" },
  { type: "RESOURCE_CONTROL_POLICY", label: "Resource control policies", short: "RCP" },
  { type: "DECLARATIVE_POLICY_EC2", label: "Declarative policies", short: "Declarative" },
  { type: "BACKUP_POLICY", label: "Backup policies", short: "Backup" },
  { type: "TAG_POLICY", label: "Tag policies", short: "Tag" },
  { type: "CHATBOT_POLICY", label: "Chat applications policies", short: "Chatbot" },
  { type: "AISERVICES_OPT_OUT_POLICY", label: "AI services opt-out policies", short: "AI opt-out" },
];

/** AWS's size limit per policy type, in characters. */
export const policyLimit = (type: string) => (type === "SERVICE_CONTROL_POLICY" || type === "RESOURCE_CONTROL_POLICY" ? 5120 : type === "AISERVICES_OPT_OUT_POLICY" ? 2500 : 10_000);

/** A starting document per policy type. */
export function example(type: string) {
  const doc: Record<string, unknown> =
    type === "SERVICE_CONTROL_POLICY"
      ? {
          Version: "2012-10-17",
          Statement: [{ Sid: "DenyOutsideRegions", Effect: "Deny", NotAction: ["iam:*", "organizations:*", "sts:*"], Resource: "*", Condition: { StringNotEquals: { "aws:RequestedRegion": ["us-east-1"] } } }],
        }
      : type === "RESOURCE_CONTROL_POLICY"
        ? { Version: "2012-10-17", Statement: [{ Sid: "EnforceTLS", Effect: "Deny", Principal: "*", Action: "s3:*", Resource: "*", Condition: { BoolIfExists: { "aws:SecureTransport": "false" } } }] }
        : type === "TAG_POLICY"
          ? { tags: { CostCenter: { tag_key: { "@@assign": "CostCenter" } } } }
          : type === "AISERVICES_OPT_OUT_POLICY"
            ? { services: { default: { opt_out_policy: { "@@assign": "optOut" } } } }
            : type === "BACKUP_POLICY"
              ? { plans: { Daily: { regions: { "@@assign": ["us-east-1"] }, rules: { Daily: { schedule_expression: { "@@assign": "cron(0 5 ? * * *)" }, target_backup_vault_name: { "@@assign": "Default" } } } } } }
              : type === "DECLARATIVE_POLICY_EC2"
                ? { ec2_attributes: { image_block_public_access: { state: { "@@assign": "block_new_sharing" } } } }
                : {};
  return JSON.stringify(doc, null, 2);
}
