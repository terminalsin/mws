import type { Rule } from "@mws-dashboard/ui";
import {
  AddUserToGroup,
  AttachRolePolicy,
  CreateGroup,
  CreatePolicy,
  CreateRole,
  CreateUser,
  PutRolePolicy,
  UpdateAssumeRolePolicy,
} from "@mws-dashboard/ui/model/iam";

// The rules IAM's forms check against: the model's constraints, refined
// with what the console knows on top (console-side only; MWS returns what
// AWS returns).

/** Service principals people usually trust, offered as you type. */
export const SERVICE_PRINCIPALS = [
  "lambda.amazonaws.com",
  "ec2.amazonaws.com",
  "ecs-tasks.amazonaws.com",
  "states.amazonaws.com",
  "events.amazonaws.com",
  "firehose.amazonaws.com",
  "scheduler.amazonaws.com",
  "eks.amazonaws.com",
  "codebuild.amazonaws.com",
  "apigateway.amazonaws.com",
];

export const RULES = {
  userName: { ...CreateUser.UserName, generate: "name" },
  roleName: { ...CreateRole.RoleName, generate: "name" },
  groupName: { ...CreateGroup.GroupName, generate: "name" },
  policyName: { ...CreatePolicy.PolicyName, generate: "name" },
  inlinePolicyName: { ...PutRolePolicy.PolicyName, generate: "name" },
  roleDescription: CreateRole.Description,
  policyDescription: CreatePolicy.Description,
  path: { ...CreateUser.Path, pattern: undefined, format: "path" },
  /** A bare service name ("lambda") gets ".amazonaws.com" added. */
  service: {
    pattern: "^[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.amazonaws\\.com$",
    hint: "A service principal, like lambda.amazonaws.com",
    known: SERVICE_PRINCIPALS,
  },
  /** Optional here: the trusted service builds one when it is empty. */
  trust: { ...CreateRole.AssumeRolePolicyDocument, required: false, format: "policy" },
  trustEdit: { ...UpdateAssumeRolePolicy.PolicyDocument, format: "policy" },
  document: { ...CreatePolicy.PolicyDocument, format: "policy" },
  policyArn: { ...AttachRolePolicy.PolicyArn, format: "arn" },
  group: AddUserToGroup.GroupName,
  member: AddUserToGroup.UserName,
} satisfies Record<string, Rule>;
