import { CloudFormationClient, CreateStackCommand, DescribeStacksCommand } from "@aws-sdk/client-cloudformation";
import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

test("CloudFormation: create a stack and see its resources and outputs", async ({ page }) => {
  const name = unique("dash-stack");
  await page.goto("/cloudformation");
  await submit(page, "create-stack", { name });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Resources").locator("li.row")).toHaveCount(2, { timeout: 1000 });
  }).toPass();
  await expect(row(page, "Queue")).toContainText("AWS::SQS::Queue");
  await page.getByRole("link", { name: /^Outputs/ }).click();
  await expect(row(page, "QueueUrl")).toContainText(name);
});

// Inline validation on the create-stack sheet: the name, template and
// parameters fields check themselves, and the template errors CloudFormation
// returns land on the field with the fix.

async function openSheet(page: Page) {
  await page.goto("/cloudformation");
  const form = page.locator("dialog[open]").getByTestId("create-stack").and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId("create-stack-open").first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, control: (name: string) => form.locator(`[name="${name}"]`) };
}

const TEMPLATE = (type: string, ref: string) => `Parameters:
  Env:
    Type: String
    Default: dev
Resources:
  Queue:
    Type: ${type}
Outputs:
  QueueUrl:
    Value: !Ref ${ref}
`;

test("CloudFormation validation: names, parameters and taken stacks are fixed in place", async ({ page }) => {
  const taken = unique("dash-cfn-taken");
  await new CloudFormationClient(sdk).send(new CreateStackCommand({ StackName: taken, TemplateBody: TEMPLATE("AWS::SQS::Queue", "Queue") }));
  const { field, control } = await openSheet(page);

  await control("name").fill("my stack");
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /my-stack/ }).click();
  await expect(control("name")).toHaveValue("my-stack");
  await expect(field("name")).not.toHaveAttribute("data-invalid");

  await control("name").fill(taken);
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(field("name").getByRole("button", { name: /Use / })).toContainText(`${taken}-2`);

  await control("parameters").fill("Env: prod");
  await control("parameters").blur();
  await expect(field("parameters")).toHaveAttribute("data-invalid", "format");
  await field("parameters").getByRole("button", { name: /Env=prod/ }).click();
  await expect(control("parameters")).toHaveValue("Env=prod");

  await control("template").fill("Resources:\n\tQueue:\n\t\tType: AWS::SQS::Queue\n");
  await control("template").blur();
  await expect(field("template")).toHaveAttribute("data-invalid", "format");
  await field("template").getByRole("button", { name: /Indent with spaces/ }).click();
  await expect(control("template")).toHaveValue("Resources:\n  Queue:\n    Type: AWS::SQS::Queue\n");
});

test("CloudFormation validation: template and parameter errors from MWS come with repairs", async ({ page }) => {
  const name = unique("dash-cfn-fix");
  const { form, field, control } = await openSheet(page);
  await control("name").fill(name);
  await control("template").fill(TEMPLATE("AWS::SQS::Queu", "Queu"));
  await control("parameters").fill("Env=prod\nStage=blue");
  const send = () => form.locator('button[type="submit"]').click();

  // A reference to nothing: the closest logical id is offered.
  await send();
  await expect(field("template")).toHaveAttribute("data-invalid", "server");
  await expect(form.locator(".result.error")).toHaveCount(0);
  await field("template").getByRole("button", { name: "Use Queue", exact: true }).click();
  await expect(control("template")).toHaveValue(TEMPLATE("AWS::SQS::Queu", "Queue"));

  // A misspelled resource type: the closest type CloudFormation knows.
  await send();
  await expect(field("template")).toHaveAttribute("data-invalid", "server");
  await field("template").getByRole("button", { name: "Use AWS::SQS::Queue", exact: true }).click();
  await expect(control("template")).toHaveValue(TEMPLATE("AWS::SQS::Queue", "Queue"));

  // A parameter the template does not declare: drop it.
  await send();
  await expect(field("parameters")).toHaveAttribute("data-invalid", "server");
  await field("parameters").getByRole("button", { name: /Remove Stage/ }).click();
  await expect(control("parameters")).toHaveValue("Env=prod");

  await send();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
});

const cfn = new CloudFormationClient(sdk);

async function stackStatus(name: string) {
  return (await cfn.send(new DescribeStacksCommand({ StackName: name }))).Stacks![0].StackStatus;
}

async function settled(name: string, status: string) {
  await expect.poll(() => stackStatus(name), { timeout: 30_000 }).toBe(status);
}

const SECRET_TEMPLATE = (extra = "") => `Parameters:
  Secret:
    Type: String
    NoEcho: true
Resources:
  Param:
    Type: AWS::SSM::Parameter
    Properties:
      Name: !Sub "/\${AWS::StackName}/secret"
      Type: String
      Value: !Ref Secret
${extra}`;

const QUEUE = `  Queue:
    Type: AWS::SQS::Queue
`;

test("CloudFormation: updating keeps a NoEcho parameter's value", async ({ page }) => {
  const name = unique("dash-cfn-noecho");
  await cfn.send(new CreateStackCommand({ StackName: name, TemplateBody: SECRET_TEMPLATE(), Parameters: [{ ParameterKey: "Secret", ParameterValue: "hunter2" }] }));
  await settled(name, "CREATE_COMPLETE");
  await page.goto(`/cloudformation/stack?name=${name}&tab=parameters`);
  await expect(page.locator("dl.facts")).toContainText("****");

  // The form shows the mask; submitting it unchanged keeps the secret.
  await submit(page, "update-stack", { template: SECRET_TEMPLATE(QUEUE) });
  await settled(name, "UPDATE_COMPLETE");
  const value = await new SSMClient(sdk).send(new GetParameterCommand({ Name: `/${name}/secret` }));
  expect(value.Parameter?.Value).toBe("hunter2");
});

test("CloudFormation: a change set previews an update and executes it", async ({ page }) => {
  const name = unique("dash-cfn-cs");
  await cfn.send(new CreateStackCommand({ StackName: name, TemplateBody: TEMPLATE("AWS::SQS::Queue", "Queue") }));
  await settled(name, "CREATE_COMPLETE");
  await page.goto(`/cloudformation/stack?name=${name}`);
  const changeSet = unique("add-topic");
  await submit(page, "create-change-set", {
    changeSet,
    template: `${TEMPLATE("AWS::SQS::Queue", "Queue")}  TopicArn:\n    Value: !Ref Topic\n`.replace("Outputs:", "  Topic:\n    Type: AWS::SNS::Topic\nOutputs:"),
    parameters: "",
  });
  await expect(page.getByRole("heading", { level: 1, name: changeSet })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(row(page, "Topic")).toContainText("Add", { timeout: 1000 });
  }).toPass();
  await page.getByTestId("execute-change-set").locator("button").click();
  await settled(name, "UPDATE_COMPLETE");
  await page.goto(`/cloudformation/stack?name=${name}`);
  await expect(row(page, "Topic")).toContainText("AWS::SNS::Topic");
});

test("CloudFormation: a stack created by a change set waits for review", async ({ page }) => {
  const name = unique("dash-cfn-review");
  const changeSet = unique("initial");
  await page.goto("/cloudformation");
  await submit(page, "create-change-set", { name, changeSet });
  await expect(page.getByRole("heading", { level: 1, name: changeSet })).toBeVisible();
  expect(await stackStatus(name)).toBe("REVIEW_IN_PROGRESS");
  await page.goto(`/cloudformation/stack?name=${name}`);
  await expect(page.locator(".banner").filter({ hasText: "waits for a change set" })).toContainText(changeSet);
  await expect(page.locator(".banner").getByRole("link", { name: changeSet })).toHaveAttribute("href", /changeset/);
  await page.goto(`/cloudformation/changeset?stack=${name}&name=${changeSet}`);
  await expect(async () => {
    await page.reload();
    await expect(page.getByTestId("execute-change-set")).toBeVisible({ timeout: 1000 });
  }).toPass();
  await page.getByTestId("execute-change-set").locator("button").click();
  await settled(name, "CREATE_COMPLETE");
});

test("CloudFormation: drift detection, termination protection and stack info", async ({ page }) => {
  const name = unique("dash-cfn-drift");
  await cfn.send(new CreateStackCommand({ StackName: name, TemplateBody: TEMPLATE("AWS::SQS::Queue", "Queue") }));
  await settled(name, "CREATE_COMPLETE");
  await page.goto(`/cloudformation/stack?name=${name}`);
  await page.getByTestId("detect-drift").locator("button").click();
  await expect(page).toHaveURL(/tab=drift/);
  await expect(row(page, "Queue")).toContainText(/in sync/i);

  await page.goto(`/cloudformation/stack?name=${name}&tab=info`);
  await expect(page.getByTestId("delete-stack")).toBeVisible();
  await page.getByTestId("termination-protection").locator("button").click();
  await expect(page.getByTestId("delete-stack")).toHaveCount(0);
  await expect(page.locator("dl.facts")).toContainText("Enabled");
  await page.getByTestId("termination-protection").locator("button").click();
  await expect(page.getByTestId("delete-stack")).toBeVisible();
});

test("CloudFormation: exports list the stacks that import them", async ({ page }) => {
  const name = unique("dash-cfn-exp");
  const exportName = `${name}-queue`;
  await cfn.send(new CreateStackCommand({ StackName: name, TemplateBody: `Resources:\n  Queue:\n    Type: AWS::SQS::Queue\nOutputs:\n  Url:\n    Value: !Ref Queue\n    Export:\n      Name: ${exportName}\n` }));
  await settled(name, "CREATE_COMPLETE");
  const user = unique("dash-cfn-imp");
  await cfn.send(new CreateStackCommand({ StackName: user, TemplateBody: `Resources:\n  Param:\n    Type: AWS::SSM::Parameter\n    Properties:\n      Type: String\n      Value: !ImportValue ${exportName}\n` }));
  await settled(user, "CREATE_COMPLETE");
  await page.goto("/cloudformation/exports");
  await expect(row(page, exportName)).toContainText(user);
  await page.goto(`/cloudformation/stack?name=${name}&tab=outputs`);
  await expect(row(page, "Url")).toContainText(user);
});

test("CloudFormation: an IMPORT change set brings an existing queue into a new stack", async ({ page }) => {
  const { CreateQueueCommand, SQSClient } = await import("@aws-sdk/client-sqs");
  const queue = unique("dash-cfn-importq");
  const url = (await new SQSClient(sdk).send(new CreateQueueCommand({ QueueName: queue }))).QueueUrl!;
  const name = unique("dash-cfn-import");
  const changeSet = unique("import");
  await page.goto("/cloudformation");
  await submit(page, "create-change-set", {
    name,
    changeSet,
    type: "IMPORT",
    template: `Resources:\n  Queue:\n    Type: AWS::SQS::Queue\n    DeletionPolicy: Retain\n    Properties:\n      QueueName: ${queue}\n`,
    imports: `Queue=${url}`,
  });
  await expect(page.getByRole("heading", { level: 1, name: changeSet })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(row(page, "Queue")).toContainText("Import", { timeout: 1000 });
  }).toPass();
  await page.getByTestId("execute-change-set").locator("button").click();
  await settled(name, "IMPORT_COMPLETE");
});

test("CloudFormation: a StackSet with automatic roles deploys a stack instance", async ({ page }) => {
  const name = unique("dash-cfn-set");
  await page.goto("/cloudformation/stacksets");
  await submit(page, "create-stack-set", { name, regions: sdk.region });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(async () => {
    await page.goto(`/cloudformation/stackset?name=${name}`);
    await expect(page.getByLabel("Stack instances").locator("li.row")).toContainText(/current|succeeded/i, { timeout: 2000 });
  }).toPass({ timeout: 40_000 });
});
