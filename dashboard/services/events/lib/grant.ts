import "server-only";

// What the AWS console does when it points a rule at a target: it adds the
// resource-policy statement that lets events.amazonaws.com deliver there.
// EventBridge (and MWS) check those policies on delivery, so without them a
// rule matches and nothing arrives.

import { DescribeResourcePoliciesCommand, PutResourcePolicyCommand } from "@aws-sdk/client-cloudwatch-logs";
import { AddPermissionCommand, GetPolicyCommand } from "@aws-sdk/client-lambda";
import { GetTopicAttributesCommand, SetTopicAttributesCommand } from "@aws-sdk/client-sns";
import { GetQueueAttributesCommand, GetQueueUrlCommand, SetQueueAttributesCommand } from "@aws-sdk/client-sqs";

import { lambda, logs, sns, sqs } from "./clients";
import { parseArn } from "./links";

type Statement = { Sid?: string; Resource?: string | string[] } & Record<string, unknown>;

const PRINCIPAL = { Service: "events.amazonaws.com" };

function sidFor(rule: string, id: string) {
  return `AWSEvents_${rule}_${id}`.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 100);
}

function withStatement(current: string | undefined, statement: Statement) {
  const policy = current ? JSON.parse(current) : { Version: "2012-10-17", Statement: [] };
  const list: Statement[] = Array.isArray(policy.Statement) ? policy.Statement : policy.Statement ? [policy.Statement] : [];
  policy.Statement = [...list.filter((s) => s.Sid !== statement.Sid), statement];
  return JSON.stringify(policy);
}

/** Grant the rule access to the target. Returns what was granted, or null
 * for targets that need a role instead (Kinesis, Firehose, buses...). */
export async function grantTarget(ruleArn: string, rule: string, id: string, targetArn: string): Promise<string | null> {
  const t = parseArn(targetArn);
  if (!t) return null;
  const Sid = sidFor(rule, id);
  const condition = { ArnEquals: { "aws:SourceArn": ruleArn } };
  switch (t.service) {
    case "sqs": {
      const client = await sqs();
      const { QueueUrl } = await client.send(new GetQueueUrlCommand({ QueueName: t.resource, QueueOwnerAWSAccountId: t.account }));
      const current = (await client.send(new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ["Policy"] }))).Attributes?.Policy;
      const Policy = withStatement(current, { Sid, Effect: "Allow", Principal: PRINCIPAL, Action: "sqs:SendMessage", Resource: targetArn, Condition: condition });
      await client.send(new SetQueueAttributesCommand({ QueueUrl, Attributes: { Policy } }));
      return "queue policy";
    }
    case "sns": {
      const client = await sns();
      const current = (await client.send(new GetTopicAttributesCommand({ TopicArn: targetArn }))).Attributes?.Policy;
      const value = withStatement(current, { Sid, Effect: "Allow", Principal: PRINCIPAL, Action: "sns:Publish", Resource: targetArn, Condition: condition });
      await client.send(new SetTopicAttributesCommand({ TopicArn: targetArn, AttributeName: "Policy", AttributeValue: value }));
      return "topic policy";
    }
    case "lambda": {
      const client = await lambda();
      const FunctionName = targetArn;
      const sids = await client
        .send(new GetPolicyCommand({ FunctionName }))
        .then((r) => ((JSON.parse(r.Policy ?? "{}").Statement ?? []) as Statement[]).map((s) => s.Sid), () => [] as (string | undefined)[]);
      if (!sids.includes(Sid)) {
        await client.send(new AddPermissionCommand({ FunctionName, StatementId: Sid, Action: "lambda:InvokeFunction", Principal: "events.amazonaws.com", SourceArn: ruleArn }));
      }
      return "function policy";
    }
    case "logs": {
      const client = await logs();
      const name = "TrustEventsToStoreLogEvent";
      const existing = (await client.send(new DescribeResourcePoliciesCommand({}))).resourcePolicies?.find((p) => p.policyName === name);
      const resource = targetArn.endsWith(":*") ? targetArn : `${targetArn}:*`;
      const policy = existing?.policyDocument ? JSON.parse(existing.policyDocument) : { Version: "2012-10-17", Statement: [] };
      const list: Statement[] = Array.isArray(policy.Statement) ? policy.Statement : [];
      const current = list.find((s) => s.Sid === name);
      const resources = new Set([...(current ? (Array.isArray(current.Resource) ? current.Resource : [current.Resource ?? ""]) : []), resource].filter(Boolean));
      policy.Statement = [
        ...list.filter((s) => s.Sid !== name),
        { Sid: name, Effect: "Allow", Principal: { Service: ["delivery.logs.amazonaws.com", "events.amazonaws.com"] }, Action: ["logs:CreateLogStream", "logs:PutLogEvents"], Resource: [...resources] },
      ];
      await client.send(new PutResourcePolicyCommand({ policyName: name, policyDocument: JSON.stringify(policy) }));
      return "log group resource policy";
    }
    default:
      return null;
  }
}
