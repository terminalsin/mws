import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { IAMClient } from "@aws-sdk/client-iam";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { client } from "@mws-dashboard/aws";

export const lambda = () => client(LambdaClient);
export const ec2 = () => client(EC2Client);
export const iam = () => client(IAMClient);

export const ICONS = {
  lambda: "service/AWSLambda",
  fn: "resource/AWSLambdaLambdaFunction",
  ec2: "service/AmazonEC2",
  instance: "resource/AmazonEC2Instance",
  ami: "resource/AmazonEC2AMI",
  sg: "resource/AmazonVPCNetworkAccessControlList",
  key: "resource/AWSIdentityAccessManagementDataEncryptionKey",
};

export const nameTag = (i: { Tags?: { Key?: string; Value?: string }[] }) => i.Tags?.find((t) => t.Key === "Name")?.Value;

/** Starter code per runtime family, for functions created in the console. */
export const STARTERS: Record<string, { file: string; handler: string; code: string }> = {
  nodejs: {
    file: "index.mjs",
    handler: "index.handler",
    code: 'export const handler = async (event) => {\n  return { statusCode: 200, body: JSON.stringify(event) };\n};\n',
  },
  python: {
    file: "lambda_function.py",
    handler: "lambda_function.lambda_handler",
    code: 'import json\n\ndef lambda_handler(event, context):\n    return {"statusCode": 200, "body": json.dumps(event)}\n',
  },
  ruby: {
    file: "lambda_function.rb",
    handler: "lambda_function.lambda_handler",
    code: "require 'json'\n\ndef lambda_handler(event:, context:)\n  { statusCode: 200, body: JSON.generate(event) }\nend\n",
  },
};

export const RUNTIMES = ["nodejs22.x", "nodejs20.x", "python3.13", "python3.12", "python3.11", "ruby3.3"];
export const family = (runtime: string) => runtime.replace(/[\d.x]+$/, "");
