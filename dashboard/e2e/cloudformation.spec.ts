import { CloudFormationClient, CreateStackCommand } from "@aws-sdk/client-cloudformation";
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
