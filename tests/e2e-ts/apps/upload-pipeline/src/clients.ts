import { S3Client } from "@aws-sdk/client-s3";
import { SNSClient } from "@aws-sdk/client-sns";
import { SQSClient } from "@aws-sdk/client-sqs";

// Region, credentials and endpoint all come from the environment. Path-style
// addressing keeps bucket names out of the host name, which matters for a
// local endpoint such as http://localhost:4566 (AWS itself accepts both).
export const s3 = new S3Client({ forcePathStyle: true });
export const sns = new SNSClient({});
export const sqs = new SQSClient({});
