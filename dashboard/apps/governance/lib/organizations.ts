import "server-only";

import {
  DescribeOrganizationCommand,
  ListAccountsForParentCommand,
  ListOrganizationalUnitsForParentCommand,
  ListPoliciesForTargetCommand,
  ListRootsCommand,
  type Account,
  type OrganizationalUnit,
  type PolicySummary,
} from "@aws-sdk/client-organizations";

import { organizations } from "./clients";

export interface OrgNode {
  id: string;
  name: string;
  kind: "root" | "ou";
  accounts: Account[];
  children: OrgNode[];
  policies: PolicySummary[];
}

/** The whole organization as a tree: root, OUs and their accounts, with
 * the SCPs attached to each node. */
export async function orgTree() {
  const client = await organizations();
  const org = (await client.send(new DescribeOrganizationCommand({}))).Organization!;
  const root = (await client.send(new ListRootsCommand({}))).Roots![0];
  const scps = (target: string) => client.send(new ListPoliciesForTargetCommand({ TargetId: target, Filter: "SERVICE_CONTROL_POLICY" })).then((r) => r.Policies ?? [], () => []);
  async function node(id: string, name: string, kind: OrgNode["kind"]): Promise<OrgNode> {
    const [ous, accounts, policies] = await Promise.all([
      client.send(new ListOrganizationalUnitsForParentCommand({ ParentId: id })).then((r) => r.OrganizationalUnits ?? []),
      client.send(new ListAccountsForParentCommand({ ParentId: id })).then((r) => r.Accounts ?? []),
      scps(id),
    ]);
    return { id, name, kind, accounts, policies, children: await Promise.all(ous.map((o: OrganizationalUnit) => node(o.Id!, o.Name!, "ou"))) };
  }
  return { org, tree: await node(root.Id!, "Root", "root") };
}

export function flatten(n: OrgNode, depth = 0): { node: OrgNode; depth: number }[] {
  return [{ node: n, depth }, ...n.children.flatMap((c) => flatten(c, depth + 1))];
}
