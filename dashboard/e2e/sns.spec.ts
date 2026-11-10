import { CreateRoleCommand, IAMClient } from "@aws-sdk/client-iam";
import { CreateFunctionCommand, GetPolicyCommand, LambdaClient } from "@aws-sdk/client-lambda";
import { CreateTopicCommand, GetSubscriptionAttributesCommand, ListSubscriptionsByTopicCommand, SNSClient, SubscribeCommand } from "@aws-sdk/client-sns";
import { CreateQueueCommand, SQSClient } from "@aws-sdk/client-sqs";
import { expect, test, type Page } from "@playwright/test";

import { strToU8, zipSync } from "fflate";

import { row, rowAction, sdk, submit, unique } from "./helpers";

test("SNS: a topic fans out to a queue", async ({ page }) => {
  const topic = unique("dash-topic");
  const queue = unique("dash-sub");
  await page.goto("/sqs");
  await submit(page, "create-queue", { name: queue });
  await page.getByRole("link", { name: queue }).click();
  const queueArn = (await page.locator("dt:has-text('ARN') + dd").first().textContent())!.trim();

  await page.goto("/sns");
  await submit(page, "create-topic", { name: topic });
  await page.getByRole("link", { name: topic }).click();
  await submit(page, "subscribe", { endpoint: queueArn });
  await expect(row(page, queue)).toBeVisible();
  await submit(page, "publish", { subject: "Hi", message: "fan-out works" });

  await page.goto(`/sqs/${queue}`);
  const peek = await submit(page, "receive-messages", { mode: "peek" });
  await expect(peek).toContainText("fan-out works");
});

// Inline validation (packages/ui validation.ts): the SNS forms check what
// SNS checks, in place, with repairs.

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  return { form, field, input: (name: string) => form.locator(`[name="${name}"]`) };
}

test("SNS validation: topic names are repaired and taken names get the next free one", async ({ page }) => {
  const topic = unique("dash-taken-topic");
  const sns = new SNSClient(sdk);
  await sns.send(new CreateTopicCommand({ Name: topic }));

  await page.goto("/sns");
  const { field, input } = await openSheet(page, "create-topic");
  await input("name").fill("Order Events (prod)");
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /Order-Events-prod/ }).click();
  await expect(input("name")).toHaveValue("Order-Events-prod");
  await expect(field("name")).not.toHaveAttribute("data-invalid");

  await input("name").fill(topic);
  await input("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await expect(field("name").getByRole("button", { name: /Use / })).toContainText(`${topic}-2`);
});

test("SNS validation: the endpoint follows the protocol and server errors land on it", async ({ page }) => {
  const topic = unique("dash-val-topic");
  const queue = unique("dash-val-queue");
  const sns = new SNSClient(sdk);
  const topicArn = (await sns.send(new CreateTopicCommand({ Name: topic }))).TopicArn!;
  const queueUrl = (await new SQSClient(sdk).send(new CreateQueueCommand({ QueueName: queue }))).QueueUrl!;
  const queueArn = topicArn.replace(":sns:", ":sqs:").replace(/:[^:]+$/, `:${queue}`);
  expect(queueUrl.endsWith(`/${queue}`)).toBe(true);

  await page.goto(`/sns/topic?arn=${encodeURIComponent(topicArn)}`);
  const { form, field, input } = await openSheet(page, "subscribe");
  const endpoint = input("endpoint");

  // SQS: a bare queue name becomes that queue's ARN.
  await endpoint.fill(queue);
  await endpoint.blur();
  await expect(field("endpoint")).toHaveAttribute("data-invalid", "format");
  await field("endpoint").getByRole("button", { name: `Use ${queue}`, exact: true }).click();
  await expect(endpoint).toHaveValue(queueArn);

  // SMS: formatting is removed for E.164.
  await form.getByTestId("protocol-sms").click();
  await endpoint.fill("+1 (415) 555-0100");
  await endpoint.blur();
  await expect(field("endpoint")).toHaveAttribute("data-invalid", "format");
  await field("endpoint").getByRole("button", { name: /\+14155550100/ }).click();
  await expect(endpoint).toHaveValue("+14155550100");

  // HTTPS: an http:// URL switches scheme.
  await form.getByTestId("protocol-https").click();
  await endpoint.fill("http://example.com/hook");
  await endpoint.blur();
  await expect(field("endpoint")).toHaveAttribute("data-invalid", "pattern");
  await field("endpoint").getByRole("button", { name: /https:\/\/example.com\/hook/ }).click();
  await expect(endpoint).toHaveValue("https://example.com/hook");

  // Email: a misspelt common domain.
  await form.getByTestId("protocol-email").click();
  await endpoint.fill("dev@gmial.com");
  await endpoint.blur();
  await field("endpoint").getByRole("button", { name: /dev@gmail.com/ }).click();
  await expect(endpoint).toHaveValue("dev@gmail.com");

  // A well-formed ARN of a queue that does not exist: the server's answer
  // lands on the endpoint, with the queue it probably meant.
  await form.getByTestId("protocol-sqs").click();
  await endpoint.fill(`${queueArn}x`);
  await form.locator('button[type="submit"]').click();
  await expect(field("endpoint")).toHaveAttribute("data-invalid", "missing");
  await expect(page.locator("dialog[open] .result.error")).toHaveCount(0);
  await field("endpoint").getByRole("button", { name: new RegExp(queue) }).click();
  await expect(endpoint).toHaveValue(queueArn);
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, queue)).toBeVisible();
});

test("SNS validation: publish checks the subject and FIFO ids", async ({ page }) => {
  const sns = new SNSClient(sdk);
  const topicArn = (
    await sns.send(new CreateTopicCommand({ Name: `${unique("dash-val-fifo")}.fifo`, Attributes: { FifoTopic: "true" } }))
  ).TopicArn!;
  await page.goto(`/sns/topic?arn=${encodeURIComponent(topicArn)}`);
  const { form, field, input } = await openSheet(page, "publish");

  await input("subject").fill("  Héllo");
  await input("subject").blur();
  await expect(field("subject")).toHaveAttribute("data-invalid", "pattern");
  await field("subject").getByRole("button", { name: /Hello/ }).click();
  await expect(input("subject")).toHaveValue("Hello");

  // Without content-based deduplication a FIFO publish needs an id.
  await input("message").fill("fifo works");
  await form.locator('button[type="submit"]').click();
  await expect(field("dedup")).toHaveAttribute("data-invalid", "required");
  await field("dedup").getByRole("button", { name: /Generate/ }).click();
  await expect(input("dedup")).not.toHaveValue("");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
});

test("SNS: confirm a pending email subscription from the console", async ({ page }) => {
  const sns = new SNSClient(sdk);
  const topicArn = (await sns.send(new CreateTopicCommand({ Name: unique("dash-confirm") }))).TopicArn!;
  const email = `${unique("dash")}@example.com`;
  await sns.send(new SubscribeCommand({ TopicArn: topicArn, Protocol: "email", Endpoint: email }));

  await page.goto(`/sns/topic?arn=${encodeURIComponent(topicArn)}`);
  await expect(row(page, email)).toContainText("pending");
  await rowAction(page, email, `Confirm ${email}`);
  // Confirmed is the normal state: only pending ones are marked.
  await expect(row(page, email)).toContainText(`Unsubscribe ${email}`);
  await expect(row(page, email)).not.toContainText("pending");
  const subs = (await sns.send(new ListSubscriptionsByTopicCommand({ TopicArn: topicArn }))).Subscriptions ?? [];
  expect(subs[0].SubscriptionArn).not.toBe("PendingConfirmation");
});

test("SNS: subscribing a function lets the topic invoke it, and the subscription's filter can be edited", async ({ page }) => {
  const sns = new SNSClient(sdk);
  const topic = unique("dash-fn-topic");
  const topicArn = (await sns.send(new CreateTopicCommand({ Name: topic }))).TopicArn!;
  const fn = unique("dash-sns-fn");
  const iam = new IAMClient(sdk);
  const role = await iam.send(
    new CreateRoleCommand({
      RoleName: fn,
      AssumeRolePolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }] }),
    }),
  );
  const lambda = new LambdaClient(sdk);
  const { FunctionArn } = await lambda.send(
    new CreateFunctionCommand({ FunctionName: fn, Runtime: "nodejs22.x", Handler: "index.handler", Role: role.Role!.Arn!, Code: { ZipFile: zipSync({ "index.js": strToU8("exports.handler = async () => 1;") }) } }),
  );

  await page.goto(`/sns/topic?arn=${encodeURIComponent(topicArn)}`);
  const sub = await openSheet(page, "subscribe");
  await sub.form.getByTestId("protocol-lambda").click();
  await sub.input("endpoint").fill(FunctionArn!);
  await sub.input("filter").fill('{"type": ["order"]}');
  await sub.form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  const policy = JSON.parse((await lambda.send(new GetPolicyCommand({ FunctionName: fn }))).Policy!);
  expect(policy.Statement[0].Principal).toEqual({ Service: "sns.amazonaws.com" });
  expect(JSON.stringify(policy.Statement[0].Condition)).toContain(topicArn);

  await row(page, fn).click();
  await expect(page.locator('pre[aria-label="Filter policy"]')).toContainText('"order"');
  await submit(page, "edit-subscription", { filter: '{"type": ["refund"]}' });
  const arn = (await sns.send(new ListSubscriptionsByTopicCommand({ TopicArn: topicArn }))).Subscriptions![0].SubscriptionArn!;
  const attrs = (await sns.send(new GetSubscriptionAttributesCommand({ SubscriptionArn: arn }))).Attributes!;
  expect(JSON.parse(attrs.FilterPolicy)).toEqual({ type: ["refund"] });
});
