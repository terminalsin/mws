import { FirehoseClient } from "@aws-sdk/client-firehose";
import { IAMClient } from "@aws-sdk/client-iam";
import { KinesisClient } from "@aws-sdk/client-kinesis";
import { S3Client } from "@aws-sdk/client-s3";

export const firehose = new FirehoseClient({});
export const iam = new IAMClient({});
export const kinesis = new KinesisClient({});
export const s3 = new S3Client({ forcePathStyle: true });
