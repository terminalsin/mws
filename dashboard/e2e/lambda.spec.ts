import { CreateRoleCommand, GetRoleCommand, IAMClient, PutRolePolicyCommand } from "@aws-sdk/client-iam";
import {
  CreateFunctionCommand,
  GetAliasCommand,
  GetFunctionCommand,
  GetPolicyCommand,
  LambdaClient,
  ListEventSourceMappingsCommand,
  waitUntilFunctionActiveV2,
} from "@aws-sdk/client-lambda";
import { CreateQueueCommand, GetQueueAttributesCommand, SQSClient } from "@aws-sdk/client-sqs";
import { expect, test, type Locator, type Page } from "@playwright/test";
import { strToU8, zipSync } from "fflate";

import { rowAction, sdk, submit, unique } from "./helpers";

const CODE = `exports.handler = async (event) => {
  console.log("got", JSON.stringify(event));
  return { greeting: "hello " + event.name };
};`;

test("Lambda: invoke, edit code and follow logs into CloudWatch", async ({ page }) => {
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

  await page.goto("/lambda");
  await page.getByRole("link", { name }).click();
  await page.getByRole("link", { name: "Test", exact: true }).click();
  const result = await submit(page, "invoke", { payload: '{"name": "console"}' });
  await expect(result).toContainText('"greeting": "hello console"');

  await page.getByRole("link", { name: "Code", exact: true }).click();
  await expect(page.getByLabel("Code")).toHaveValue(/hello " \+ event.name/);
  await submit(page, "save-code", { code: CODE.replace('"hello "', '"hi "') });
  await waitUntilFunctionActiveV2({ client: lambda, maxWaitTime: 60 }, { FunctionName: name });
  await page.getByRole("link", { name: "Test", exact: true }).click();
  await expect(await submit(page, "invoke", { payload: '{"name": "again"}' })).toContainText('"greeting": "hi again"');

  await page.getByRole("link", { name: "View logs" }).click();
  await expect(page.getByRole("heading", { level: 1, name: `/aws/lambda/${name}` })).toBeVisible();
  await expect(page.getByRole("list", { name: "Log events" })).toContainText('got {"name":"console"}');
});

test("Lambda: create a function with an automatic execution role", async ({ page }) => {
  const name = unique("dash-new");
  await page.goto("/lambda");
  await page.getByTestId("create-function-open").click();
  const form = page.getByTestId("create-function").and(page.locator("form"));
  await form.locator('[name="name"]').fill(name);
  await form.getByTestId("execution-role").getByRole("button", { name: "Create automatically" }).click();
  await expect(form.getByTestId("execution-role-auto")).toBeVisible();
  await form.locator('button[type="submit"]').click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const role = await new IAMClient(sdk).send(new GetRoleCommand({ RoleName: `${name}-role` }));
  expect(decodeURIComponent(role.Role!.AssumeRolePolicyDocument!)).toContain("lambda.amazonaws.com");
});

async function lambdaRole(name: string) {
  const role = await new IAMClient(sdk).send(
    new CreateRoleCommand({
      RoleName: name,
      AssumeRolePolicyDocument: JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }],
      }),
    }),
  );
  return role.Role!.Arn!;
}

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  return form;
}

const fieldOf = (form: Locator, name: string) => form.locator(".field").filter({ has: form.page().locator(`[name="${name}"]`) });

test("Lambda: create form repairs names in place", async ({ page }) => {
  const taken = unique("dash-taken-fn");
  const lambda = new LambdaClient(sdk);
  await lambda.send(
    new CreateFunctionCommand({ FunctionName: taken, Runtime: "nodejs22.x", Handler: "index.handler", Role: await lambdaRole(taken), Code: { ZipFile: zipSync({ "index.js": strToU8(CODE) }) } }),
  );

  await page.goto("/lambda");
  const form = await openSheet(page, "create-function");
  const name = form.locator('[name="name"]');
  const field = fieldOf(form, "name");

  await name.fill("Order Handler");
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "pattern");
  await field.getByRole("button", { name: /Replace spaces/ }).click();
  await expect(name).toHaveValue("Order-Handler");
  await expect(field).not.toHaveAttribute("data-invalid");

  await name.fill(taken);
  await name.blur();
  await expect(field).toHaveAttribute("data-invalid", "taken");
  await field.getByRole("button", { name: /Use / }).click();
  await expect(name).toHaveValue(`${taken}-2`);
});

test("Lambda: configuration and test event fields offer repairs", async ({ page }) => {
  const name = unique("dash-cfg");
  const lambda = new LambdaClient(sdk);
  const roleArn = await lambdaRole(name);
  await lambda.send(
    new CreateFunctionCommand({ FunctionName: name, Runtime: "nodejs22.x", Handler: "index.handler", Role: roleArn, Code: { ZipFile: zipSync({ "index.js": strToU8(CODE) }) } }),
  );
  await waitUntilFunctionActiveV2({ client: lambda, maxWaitTime: 60 }, { FunctionName: name });

  // The test event is JSON; hand-written mistakes get a one-click fix.
  await page.goto(`/lambda/${name}?tab=test`);
  const invoke = page.getByTestId("invoke").and(page.locator("form"));
  const payload = invoke.locator('[name="payload"]');
  // Typed before hydration, the value may be lost or merged with the
  // default: retry until the field follows exactly what was typed.
  const fixJson = fieldOf(invoke, "payload").getByRole("button", { name: "Fix the JSON" });
  await expect(async () => {
    await payload.fill("{name: 'console',}");
    await payload.blur();
    await expect(payload).toHaveValue("{name: 'console',}", { timeout: 500 });
    await expect(fixJson).toBeVisible({ timeout: 1000 });
  }).toPass();
  await fixJson.click();
  await expect(payload).toHaveValue('{\n  "name": "console"\n}');
  await invoke.locator('button[type="submit"]').click();
  await expect(invoke.getByRole("status")).toContainText('"greeting": "hello console"');

  await page.goto(`/lambda/${name}?tab=config`);
  const form = await openSheet(page, "edit-config");

  // Over the limit: clamped.
  const memory = form.locator('[name="memory"]');
  await memory.fill("20000");
  await memory.blur();
  await expect(fieldOf(form, "memory")).toHaveAttribute("data-invalid", "range");
  await fieldOf(form, "memory").getByRole("button", { name: /10240/ }).click();
  await expect(memory).toHaveValue("10240");

  // A bare role name resolves to the known role's ARN.
  const role = form.locator('[name="role"]');
  await role.fill(name);
  await role.blur();
  await expect(fieldOf(form, "role")).toHaveAttribute("data-invalid", "format");
  await fieldOf(form, "role").getByRole("button", { name: `Use ${name}` }).click();
  await expect(role).toHaveValue(roleArn);

  // .env habits are fixed and keys Lambda reserves are dropped.
  const env = form.locator('[name="env"]');
  await env.fill('export log-level="debug"\nAWS_REGION=us-east-1');
  await env.blur();
  await expect(fieldOf(form, "env")).toContainText("log-level");
  await fieldOf(form, "env").getByRole("button", { name: /Fix the keys/ }).click();
  await expect(env).toHaveValue("LOG_LEVEL=debug");

  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  const cfg = await lambda.send(new GetFunctionCommand({ FunctionName: name }));
  expect(cfg.Configuration!.MemorySize).toBe(10240);
  expect(cfg.Configuration!.Environment!.Variables).toEqual({ LOG_LEVEL: "debug" });
});

async function seededFunction(prefix: string, code = CODE) {
  const name = unique(prefix);
  const lambda = new LambdaClient(sdk);
  await lambda.send(
    new CreateFunctionCommand({ FunctionName: name, Runtime: "nodejs22.x", Handler: "index.handler", Role: await lambdaRole(name), Code: { ZipFile: zipSync({ "index.js": strToU8(code) }) } }),
  );
  await waitUntilFunctionActiveV2({ client: lambda, maxWaitTime: 60 }, { FunctionName: name });
  return { name, lambda };
}

test("Lambda: a public function URL gets the policy AWS's console adds and answers on MWS", async ({ page }) => {
  const { name, lambda } = await seededFunction("dash-url", `exports.handler = async () => ({ statusCode: 200, body: "from the url" });`);
  await page.goto(`/lambda/${name}?tab=config`);
  await submit(page, "create-url", { auth: "NONE" });
  const policy = JSON.parse((await lambda.send(new GetPolicyCommand({ FunctionName: name }))).Policy!);
  const sids = policy.Statement.map((s: { Sid: string }) => s.Sid);
  expect(sids).toEqual(expect.arrayContaining(["FunctionURLAllowPublicAccess", "FunctionURLAllowInvokeAction"]));
  await page.reload();
  const href = await page.getByTestId("function-url").getAttribute("href");
  expect(href).toContain("/_aws/lambda-url/");
  const response = await fetch(href!);
  expect(response.status).toBe(200);
  expect(await response.text()).toBe("from the url");
});

test("Lambda: add an SQS trigger and a resource-based permission", async ({ page }) => {
  const { name, lambda } = await seededFunction("dash-trig");
  const queue = unique("dash-trig-q");
  const sqs = new SQSClient(sdk);
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: queue }));
  const queueArn = (await sqs.send(new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ["QueueArn"] }))).Attributes!.QueueArn!;

  await page.goto(`/lambda/${name}?tab=triggers`);
  await submit(page, "add-trigger", { source: queueArn, batch: "5", grant: "on" });
  const mappings = (await lambda.send(new ListEventSourceMappingsCommand({ FunctionName: name }))).EventSourceMappings ?? [];
  expect(mappings.map((m) => [m.EventSourceArn, m.BatchSize])).toEqual([[queueArn, 5]]);
  await page.reload();
  await expect(page.locator("li.row").filter({ hasText: queue })).toBeVisible();

  await page.goto(`/lambda/${name}?tab=permissions`);
  const topicArn = queueArn.replace(":sqs:", ":sns:");
  await submit(page, "add-permission", { sid: "from-sns", principal: "sns.amazonaws.com", sourceArn: topicArn });
  const statement = JSON.parse((await lambda.send(new GetPolicyCommand({ FunctionName: name }))).Policy!).Statement.find((s: { Sid: string }) => s.Sid === "from-sns");
  expect(statement.Principal).toEqual({ Service: "sns.amazonaws.com" });
  expect(JSON.stringify(statement.Condition)).toContain(topicArn);
  await page.reload();
  await rowAction(page, "from-sns", "Remove from-sns");
  await expect(page.locator("li.row").filter({ hasText: "from-sns" })).toHaveCount(0);
});

test("Lambda: publish a version, point an alias at it and invoke it", async ({ page }) => {
  const { name, lambda } = await seededFunction("dash-alias");
  await page.goto(`/lambda/${name}?tab=versions`);
  await submit(page, "publish-version", { description: "first" });
  await page.goto(`/lambda/${name}?tab=aliases`);
  await submit(page, "create-alias", { alias: "live", version: "1" });
  const alias = await lambda.send(new GetAliasCommand({ FunctionName: name, Name: "live" }));
  expect(alias.FunctionVersion).toBe("1");
  await page.goto(`/lambda/${name}?tab=test&qualifier=live`);
  const result = await submit(page, "invoke", { payload: '{"name": "alias"}' });
  await expect(result).toContainText("· 1");
});
