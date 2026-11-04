// Provisions the pipeline the way an IaC tool would:
//
//   S3 bucket --(uploads/ prefix, ObjectCreated)--> SNS topic
//        SNS topic --> "indexer" SQS queue (raw delivery, DLQ after 2 tries)
//        SNS topic --> "audit" SQS queue (SNS envelope kept)
//
// Every hop is guarded by a resource policy, as in a real account: the topic
// policy lets S3 publish for this bucket only, and the queue policies let SNS
// send for this topic only.
import {
  CreateBucketCommand,
  PutBucketNotificationConfigurationCommand,
} from "@aws-sdk/client-s3";
import { CreateTopicCommand, SetTopicAttributesCommand, SubscribeCommand } from "@aws-sdk/client-sns";
import { CreateQueueCommand, GetQueueAttributesCommand, SetQueueAttributesCommand } from "@aws-sdk/client-sqs";
import { s3, sns, sqs } from "./clients.js";

export interface Pipeline {
  bucket: string;
  topicArn: string;
  indexQueueUrl: string;
  auditQueueUrl: string;
  deadLetterQueueUrl: string;
}

async function createQueue(name: string, attributes: Record<string, string> = {}) {
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: name, Attributes: attributes }));
  const { Attributes } = await sqs.send(
    new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ["QueueArn"] }),
  );
  return { url: QueueUrl!, arn: Attributes!.QueueArn! };
}

async function allowTopicToSend(queue: { url: string; arn: string }, topicArn: string) {
  const policy = {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: { Service: "sns.amazonaws.com" },
        Action: "sqs:SendMessage",
        Resource: queue.arn,
        Condition: { ArnEquals: { "aws:SourceArn": topicArn } },
      },
    ],
  };
  await sqs.send(
    new SetQueueAttributesCommand({ QueueUrl: queue.url, Attributes: { Policy: JSON.stringify(policy) } }),
  );
}

export async function provisionPipeline(name: string): Promise<Pipeline> {
  const bucket = `${name}-documents`;
  await s3.send(new CreateBucketCommand({ Bucket: bucket }));

  const { TopicArn } = await sns.send(new CreateTopicCommand({ Name: `${name}-uploads` }));
  const topicArn = TopicArn!;
  await sns.send(
    new SetTopicAttributesCommand({
      TopicArn: topicArn,
      AttributeName: "Policy",
      AttributeValue: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Principal: { Service: "s3.amazonaws.com" },
            Action: "sns:Publish",
            Resource: topicArn,
            Condition: { ArnLike: { "aws:SourceArn": `arn:aws:s3:::${bucket}` } },
          },
        ],
      }),
    }),
  );

  const dlq = await createQueue(`${name}-indexer-dlq`);
  const indexQueue = await createQueue(`${name}-indexer`, {
    VisibilityTimeout: "30",
    RedrivePolicy: JSON.stringify({ deadLetterTargetArn: dlq.arn, maxReceiveCount: 2 }),
  });
  const auditQueue = await createQueue(`${name}-audit`);

  for (const queue of [indexQueue, auditQueue]) {
    await allowTopicToSend(queue, topicArn);
  }
  await sns.send(
    new SubscribeCommand({
      TopicArn: topicArn,
      Protocol: "sqs",
      Endpoint: indexQueue.arn,
      Attributes: { RawMessageDelivery: "true" },
    }),
  );
  await sns.send(new SubscribeCommand({ TopicArn: topicArn, Protocol: "sqs", Endpoint: auditQueue.arn }));

  // S3 checks that it may publish to the topic and sends it an s3:TestEvent.
  await s3.send(
    new PutBucketNotificationConfigurationCommand({
      Bucket: bucket,
      NotificationConfiguration: {
        TopicConfigurations: [
          {
            Id: "uploads",
            TopicArn: topicArn,
            Events: ["s3:ObjectCreated:*"],
            Filter: { Key: { FilterRules: [{ Name: "prefix", Value: "uploads/" }] } },
          },
        ],
      },
    }),
  );

  return {
    bucket,
    topicArn,
    indexQueueUrl: indexQueue.url,
    auditQueueUrl: auditQueue.url,
    deadLetterQueueUrl: dlq.url,
  };
}
