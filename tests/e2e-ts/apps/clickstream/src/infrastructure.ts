// Kinesis data stream --> Firehose delivery stream --> S3 data lake
//
// Firehose reads the stream and writes gzipped batches under
// clicks/year=YYYY/month=MM/day=DD/, with failed records under errors/.
import { CreateDeliveryStreamCommand, DescribeDeliveryStreamCommand } from "@aws-sdk/client-firehose";
import { CreateRoleCommand, PutRolePolicyCommand } from "@aws-sdk/client-iam";
import { CreateStreamCommand, DescribeStreamSummaryCommand, waitUntilStreamExists } from "@aws-sdk/client-kinesis";
import { CreateBucketCommand } from "@aws-sdk/client-s3";
import { firehose, iam, kinesis, s3 } from "./clients.js";

export interface Clickstream {
  streamName: string;
  deliveryStreamName: string;
  bucket: string;
}

/** Firehose has no SDK waiter: poll until the stream leaves CREATING. */
async function waitForActive(deliveryStreamName: string): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    const { DeliveryStreamDescription } = await firehose.send(
      new DescribeDeliveryStreamCommand({ DeliveryStreamName: deliveryStreamName }),
    );
    const status = DeliveryStreamDescription!.DeliveryStreamStatus;
    if (status === "ACTIVE") return;
    if (status !== "CREATING") throw new Error(`delivery stream is ${status}`);
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`delivery stream ${deliveryStreamName} did not become ACTIVE`);
}

export async function provisionClickstream(name: string): Promise<Clickstream> {
  const streamName = `${name}-clicks`;
  await kinesis.send(new CreateStreamCommand({ StreamName: streamName, ShardCount: 2 }));
  await waitUntilStreamExists({ client: kinesis, maxWaitTime: 60 }, { StreamName: streamName });
  const { StreamDescriptionSummary } = await kinesis.send(new DescribeStreamSummaryCommand({ StreamName: streamName }));
  const streamArn = StreamDescriptionSummary!.StreamARN!;

  const bucket = `${name}-datalake`;
  await s3.send(new CreateBucketCommand({ Bucket: bucket }));

  // Firehose works as this role: it reads the stream and writes the bucket.
  const roleName = `${name}-firehose`;
  const { Role } = await iam.send(
    new CreateRoleCommand({
      RoleName: roleName,
      AssumeRolePolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Principal: { Service: "firehose.amazonaws.com" }, Action: "sts:AssumeRole" }],
      }),
    }),
  );
  await iam.send(
    new PutRolePolicyCommand({
      RoleName: roleName,
      PolicyName: "delivery",
      PolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Effect: "Allow",
            Action: ["kinesis:DescribeStream", "kinesis:DescribeStreamSummary", "kinesis:GetShardIterator", "kinesis:GetRecords", "kinesis:ListShards"],
            Resource: streamArn,
          },
          {
            Effect: "Allow",
            Action: ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket", "s3:AbortMultipartUpload"],
            Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`],
          },
        ],
      }),
    }),
  );

  const deliveryStreamName = `${name}-to-s3`;
  await firehose.send(
    new CreateDeliveryStreamCommand({
      DeliveryStreamName: deliveryStreamName,
      DeliveryStreamType: "KinesisStreamAsSource",
      KinesisStreamSourceConfiguration: { KinesisStreamARN: streamArn, RoleARN: Role!.Arn },
      ExtendedS3DestinationConfiguration: {
        BucketARN: `arn:aws:s3:::${bucket}`,
        RoleARN: Role!.Arn,
        Prefix: "clicks/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
        ErrorOutputPrefix: "errors/!{firehose:error-output-type}/",
        CompressionFormat: "GZIP",
        BufferingHints: { IntervalInSeconds: 60, SizeInMBs: 5 },
      },
    }),
  );
  await waitForActive(deliveryStreamName);

  return { streamName, deliveryStreamName, bucket };
}
