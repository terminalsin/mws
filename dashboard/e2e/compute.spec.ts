import { CreateRoleCommand, IAMClient, PutRolePolicyCommand } from "@aws-sdk/client-iam";
import { CreateFunctionCommand, LambdaClient, waitUntilFunctionActiveV2 } from "@aws-sdk/client-lambda";
import { expect, test } from "@playwright/test";
import { strToU8, zipSync } from "fflate";

import { sdk, submit, unique } from "./helpers";

const CODE = `exports.handler = async (event) => {
  console.log("got", JSON.stringify(event));
  return { greeting: "hello " + event.name };
};`;

test("Lambda: invoke a function and follow its logs into another zone", async ({ page }) => {
  const name = unique("dash-fn");
  const iam = new IAMClient(sdk);
  const lambda = new LambdaClient(sdk);
  const role = await iam.send(
    new CreateRoleCommand({
      RoleName: name,
      AssumeRolePolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }],
      }),
    }),
  );
  // Without this the function runs but, as in AWS, cannot write its logs.
  await iam.send(
    new PutRolePolicyCommand({
      RoleName: name,
      PolicyName: "logs",
      PolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Action: ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource: "*" }],
      }),
    }),
  );
  await lambda.send(
    new CreateFunctionCommand({
      FunctionName: name,
      Runtime: "nodejs22.x",
      Handler: "index.handler",
      Role: role.Role!.Arn,
      Code: { ZipFile: zipSync({ "index.js": strToU8(CODE) }) },
    }),
  );
  await waitUntilFunctionActiveV2({ client: lambda, maxWaitTime: 60 }, { FunctionName: name });

  await page.goto("/compute/lambda");
  await page.getByRole("link", { name }).click();
  const result = await submit(page, "invoke", { payload: '{"name": "console"}' });
  await expect(result).toContainText('"greeting": "hello console"');

  await page.getByRole("link", { name: "View logs" }).click();
  await expect(page.getByRole("heading", { level: 1, name: `/aws/lambda/${name}` })).toBeVisible();
  await expect(page.getByRole("table", { name: "Log events" })).toContainText('got {"name":"console"}');
});

test("EC2: the default VPC is listed", async ({ page }) => {
  await page.goto("/compute/ec2");
  await expect(page.getByRole("table", { name: "VPCs" })).toContainText("default");
});
