import "server-only";

import { IAMClient } from "@aws-sdk/client-iam";
import { KinesisClient } from "@aws-sdk/client-kinesis";
import { LambdaClient } from "@aws-sdk/client-lambda";
import { SQSClient } from "@aws-sdk/client-sqs";
import { client, endpoint } from "@mws-dashboard/aws";

export const lambda = () => client(LambdaClient);
export const iam = () => client(IAMClient);
export const sqs = () => client(SQSClient);
export const kinesis = () => client(KinesisClient);

/** Where MWS serves a function URL (`https://<id>.lambda-url.<region>.on.aws/`
 * resolves to AWS, not MWS): `<endpoint>/_aws/lambda-url/<id>/`. */
export function urlOnMws(url: string): string {
  const id = new URL(url).hostname.split(".")[0];
  return `${endpoint()}/_aws/lambda-url/${id}/`;
}

export const ICONS = {
  lambda: "service/AWSLambda",
  fn: "resource/AWSLambdaLambdaFunction",
};

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

export const RUNTIMES = ["nodejs22.x", "nodejs20.x", "python3.13", "python3.12", "python3.11", "ruby3.3", "java21", "java17", "dotnet8", "provided.al2023"];
export const family = (runtime: string) => runtime.replace(/[\d.x]+$/, "");
