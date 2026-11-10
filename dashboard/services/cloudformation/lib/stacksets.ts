import "server-only";

import { CreateRoleCommand, GetRoleCommand, IAMClient, NoSuchEntityException, PutRolePolicyCommand } from "@aws-sdk/client-iam";
import { client } from "@mws-dashboard/aws";
import { ensureRole } from "@mws-dashboard/aws/auto";

export const ADMIN_ROLE = "AWSCloudFormationStackSetAdministrationRole";
export const EXECUTION_ROLE = "AWSCloudFormationStackSetExecutionRole";

/** The two roles a self-managed stack set runs with, as AWS's setup
 * template makes them: CloudFormation assumes the administration role, which
 * assumes the execution role in each target account (here, this one). */
export async function ensureStackSetRoles(account: string): Promise<string> {
  const admin = await ensureRole({
    name: ADMIN_ROLE,
    service: "cloudformation.amazonaws.com",
    statements: [{ Effect: "Allow", Action: "sts:AssumeRole", Resource: `arn:aws:iam::*:role/${EXECUTION_ROLE}` }],
  });
  const iam = await client(IAMClient);
  try {
    await iam.send(new GetRoleCommand({ RoleName: EXECUTION_ROLE }));
  } catch (e) {
    if (!(e instanceof NoSuchEntityException)) throw e;
    await iam.send(
      new CreateRoleCommand({
        RoleName: EXECUTION_ROLE,
        AssumeRolePolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${account}:root` }, Action: "sts:AssumeRole" }] }),
        Description: "Created by the MWS console",
        Tags: [{ Key: "mws:console", Value: "auto" }],
      }),
    );
  }
  await iam.send(new PutRolePolicyCommand({ RoleName: EXECUTION_ROLE, PolicyName: "console-permissions", PolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] }) }));
  return admin;
}
