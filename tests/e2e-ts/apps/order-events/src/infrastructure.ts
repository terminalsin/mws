// Provisions the order-processing flow:
//
//   checkout --OrderPlaced--> custom event bus
//     rule "all-orders"        --> SQS audit queue (InputTransformer)
//     rule "high-value-orders" --> Lambda fraud-check --FraudCheckCompleted--> bus
//     rule "fraud-results"     --> SQS results queue
import {
  CreateEventBusCommand,
  PutRuleCommand,
  PutTargetsCommand,
  type Target,
} from "@aws-sdk/client-eventbridge";
import { CreateRoleCommand, PutRolePolicyCommand } from "@aws-sdk/client-iam";
import { AddPermissionCommand, CreateFunctionCommand, waitUntilFunctionActiveV2 } from "@aws-sdk/client-lambda";
import { CreateQueueCommand, GetQueueAttributesCommand, SetQueueAttributesCommand } from "@aws-sdk/client-sqs";
import { fileURLToPath } from "node:url";
import { bundleFunction } from "./bundle.js";
import { events, iam, lambda, sqs } from "./clients.js";
import { FRAUD_SOURCE, ORDER_SOURCE } from "./model.js";

export interface OrderFlow {
  eventBusName: string;
  functionName: string;
  auditQueueUrl: string;
  resultsQueueUrl: string;
  highValuePattern: string;
}

export const HIGH_VALUE_PATTERN = {
  source: [ORDER_SOURCE],
  "detail-type": ["OrderPlaced"],
  detail: { total: [{ numeric: [">=", 500] }] },
};

async function putRule(eventBusName: string, name: string, pattern: object, target: Target) {
  const { RuleArn } = await events.send(
    new PutRuleCommand({ Name: name, EventBusName: eventBusName, EventPattern: JSON.stringify(pattern) }),
  );
  const { FailedEntryCount, FailedEntries } = await events.send(
    new PutTargetsCommand({ Rule: name, EventBusName: eventBusName, Targets: [target] }),
  );
  if (FailedEntryCount) throw new Error(JSON.stringify(FailedEntries));
  return RuleArn!;
}

/** A queue whose policy lets EventBridge deliver from the given rule. */
async function queueForRule(queueName: string, ruleArn: string) {
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: queueName }));
  const { Attributes } = await sqs.send(
    new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ["QueueArn"] }),
  );
  const queueArn = Attributes!.QueueArn!;
  await sqs.send(
    new SetQueueAttributesCommand({
      QueueUrl,
      Attributes: {
        Policy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: { Service: "events.amazonaws.com" },
              Action: "sqs:SendMessage",
              Resource: queueArn,
              Condition: { ArnEquals: { "aws:SourceArn": ruleArn } },
            },
          ],
        }),
      },
    }),
  );
  return { url: QueueUrl!, arn: queueArn };
}

async function deployFraudCheck(name: string, eventBusName: string, eventBusArn: string) {
  const roleName = `${name}-fraud-check`;
  const { Role } = await iam.send(
    new CreateRoleCommand({
      RoleName: roleName,
      AssumeRolePolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          { Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" },
        ],
      }),
    }),
  );
  await iam.send(
    new PutRolePolicyCommand({
      RoleName: roleName,
      PolicyName: "fraud-check",
      PolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          { Effect: "Allow", Action: "events:PutEvents", Resource: eventBusArn },
          {
            Effect: "Allow",
            Action: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            Resource: "*",
          },
        ],
      }),
    }),
  );

  const functionName = `${name}-fraud-check`;
  const entryPoint = fileURLToPath(new URL("./functions/fraud-check.ts", import.meta.url));
  const { FunctionArn } = await lambda.send(
    new CreateFunctionCommand({
      FunctionName: functionName,
      Runtime: "nodejs22.x",
      Handler: "index.handler",
      Role: Role!.Arn,
      Code: { ZipFile: await bundleFunction(entryPoint) },
      Timeout: 15,
      Environment: { Variables: { EVENT_BUS_NAME: eventBusName } },
    }),
  );
  await waitUntilFunctionActiveV2({ client: lambda, maxWaitTime: 60 }, { FunctionName: functionName });
  return { functionName, functionArn: FunctionArn! };
}

export async function provisionOrderFlow(name: string): Promise<OrderFlow> {
  const eventBusName = `${name}-orders`;
  const { EventBusArn } = await events.send(new CreateEventBusCommand({ Name: eventBusName }));
  const { functionName, functionArn } = await deployFraudCheck(name, eventBusName, EventBusArn!);

  // Every order, reshaped for the audit log.
  const allOrdersArn = `${EventBusArn!.replace(":event-bus/", ":rule/")}/all-orders`;
  const audit = await queueForRule(`${name}-order-audit`, allOrdersArn);
  await putRule(
    eventBusName,
    "all-orders",
    { source: [ORDER_SOURCE], "detail-type": ["OrderPlaced"] },
    {
      Id: "audit-queue",
      Arn: audit.arn,
      InputTransformer: {
        InputPathsMap: { id: "$.detail.orderId", total: "$.detail.total", at: "$.time" },
        InputTemplate: '{"orderId": <id>, "total": <total>, "placedAt": <at>}',
      },
    },
  );

  // High-value orders go through the fraud check.
  const highValueArn = await putRule(eventBusName, "high-value-orders", HIGH_VALUE_PATTERN, {
    Id: "fraud-check",
    Arn: functionArn,
  });
  await lambda.send(
    new AddPermissionCommand({
      FunctionName: functionName,
      StatementId: "eventbridge-high-value-orders",
      Action: "lambda:InvokeFunction",
      Principal: "events.amazonaws.com",
      SourceArn: highValueArn,
    }),
  );

  const resultsArn = `${EventBusArn!.replace(":event-bus/", ":rule/")}/fraud-results`;
  const results = await queueForRule(`${name}-fraud-results`, resultsArn);
  await putRule(
    eventBusName,
    "fraud-results",
    { source: [FRAUD_SOURCE], "detail-type": ["FraudCheckCompleted"] },
    { Id: "results-queue", Arn: results.arn },
  );

  return {
    eventBusName,
    functionName,
    auditQueueUrl: audit.url,
    resultsQueueUrl: results.url,
    highValuePattern: JSON.stringify(HIGH_VALUE_PATTERN),
  };
}
