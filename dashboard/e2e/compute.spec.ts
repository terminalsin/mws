import { CreateRoleCommand, IAMClient, PutRolePolicyCommand } from "@aws-sdk/client-iam";
import { CreateFunctionCommand, LambdaClient, waitUntilFunctionActiveV2 } from "@aws-sdk/client-lambda";
import { expect, test } from "@playwright/test";
import { strToU8, zipSync } from "fflate";

import { row, sdk, submit, unique } from "./helpers";

const CODE = `exports.handler = async (event) => {
  console.log("got", JSON.stringify(event));
  return { greeting: "hello " + event.name };
};`;

test("Lambda: invoke, edit code and follow logs into another zone", async ({ page }) => {
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

  await page.getByRole("link", { name: "Code" }).click();
  await expect(page.getByLabel("Code")).toHaveValue(/hello " \+ event.name/);
  await submit(page, "save-code", { code: CODE.replace('"hello "', '"hi "') });
  await waitUntilFunctionActiveV2({ client: lambda, maxWaitTime: 60 }, { FunctionName: name });
  await page.getByRole("link", { name: "Test" }).click();
  await expect(await submit(page, "invoke", { payload: '{"name": "again"}' })).toContainText('"greeting": "hi again"');

  await page.getByRole("link", { name: "View logs" }).click();
  await expect(page.getByRole("heading", { level: 1, name: `/aws/lambda/${name}` })).toBeVisible();
  await expect(page.getByRole("list", { name: "Log events" })).toContainText('got {"name":"console"}');
});

test("Lambda: create a function from the console", async ({ page }) => {
  const name = unique("dash-new");
  const iam = new IAMClient(sdk);
  const role = await iam.send(
    new CreateRoleCommand({
      RoleName: name,
      AssumeRolePolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }],
      }),
    }),
  );
  await page.goto("/compute/lambda");
  await page.getByTestId("create-function-open").click();
  const form = page.getByTestId("create-function").and(page.locator("form"));
  await form.locator('[name="name"]').fill(name);
  await form.locator('[name="role"]').fill(role.Role!.Arn!);
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
});

test("EC2: security groups flag ports open to the internet", async ({ page }) => {
  const group = unique("dash-sg");
  await page.goto("/compute/ec2?tab=groups");
  await submit(page, "create-security-group", { name: group });
  await row(page, group).getByRole("button", { name: `Allow inbound to ${group}` }).click();
  const form = page.locator("dialog[open] form");
  await form.locator('[name="ports"]').fill("22");
  await form.locator('[name="cidr"]').fill("0.0.0.0/0");
  await form.locator('button[type="submit"]').click();
  await expect(row(page, group).locator(".chip.bad")).toContainText("22 ← anywhere");
});
