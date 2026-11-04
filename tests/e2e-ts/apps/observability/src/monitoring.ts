// The monitoring setup for a "checkout" service:
//
//   log group  --metric filter { $.level = "ERROR" }-->  Checkout/Errors
//   alarm: Checkout/Errors Sum >= 3 in a minute  -->  SNS topic  -->  SQS "pager" queue
import { PutMetricAlarmCommand } from "@aws-sdk/client-cloudwatch";
import { CreateLogGroupCommand, PutMetricFilterCommand, PutRetentionPolicyCommand } from "@aws-sdk/client-cloudwatch-logs";
import { CreateTopicCommand, SubscribeCommand } from "@aws-sdk/client-sns";
import { CreateQueueCommand, GetQueueAttributesCommand, SetQueueAttributesCommand } from "@aws-sdk/client-sqs";
import { cloudwatch, logs, sns, sqs } from "./clients.js";

export interface Monitoring {
  logGroupName: string;
  namespace: string;
  alarmName: string;
  pagerQueueUrl: string;
}

export async function provisionMonitoring(name: string): Promise<Monitoring> {
  const logGroupName = `/app/${name}/checkout`;
  const namespace = `${name}/Checkout`;
  await logs.send(new CreateLogGroupCommand({ logGroupName }));
  await logs.send(new PutRetentionPolicyCommand({ logGroupName, retentionInDays: 14 }));
  await logs.send(
    new PutMetricFilterCommand({
      logGroupName,
      filterName: "errors",
      filterPattern: '{ $.level = "ERROR" }',
      metricTransformations: [{ metricNamespace: namespace, metricName: "Errors", metricValue: "1", defaultValue: 0 }],
    }),
  );

  const { TopicArn } = await sns.send(new CreateTopicCommand({ Name: `${name}-alerts` }));
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: `${name}-pager` }));
  const { Attributes } = await sqs.send(new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ["QueueArn"] }));
  await sqs.send(
    new SetQueueAttributesCommand({
      QueueUrl,
      Attributes: {
        Policy: JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Effect: "Allow",
              Principal: { Service: "sns.amazonaws.com" },
              Action: "sqs:SendMessage",
              Resource: Attributes!.QueueArn,
              Condition: { ArnEquals: { "aws:SourceArn": TopicArn } },
            },
          ],
        }),
      },
    }),
  );
  await sns.send(
    new SubscribeCommand({
      TopicArn,
      Protocol: "sqs",
      Endpoint: Attributes!.QueueArn,
      Attributes: { RawMessageDelivery: "true" },
    }),
  );

  const alarmName = `${name}-checkout-errors`;
  await cloudwatch.send(
    new PutMetricAlarmCommand({
      AlarmName: alarmName,
      AlarmDescription: "Checkout is logging errors",
      Namespace: namespace,
      MetricName: "Errors",
      Statistic: "Sum",
      Period: 60,
      EvaluationPeriods: 1,
      Threshold: 3,
      ComparisonOperator: "GreaterThanOrEqualToThreshold",
      TreatMissingData: "notBreaching",
      AlarmActions: [TopicArn!],
      OKActions: [TopicArn!],
    }),
  );

  return { logGroupName, namespace, alarmName, pagerQueueUrl: QueueUrl! };
}
