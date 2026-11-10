import { CreateTopicCommand, SNSClient } from "@aws-sdk/client-sns";
import { CreateQueueCommand, SQSClient } from "@aws-sdk/client-sqs";
import { expect, test, type Page } from "@playwright/test";

import { row, sdk, submit, unique } from "./helpers";

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
  await submit(page, "subscribe", { protocol: "sqs", endpoint: queueArn });
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
  await input("protocol").selectOption("sms");
  await endpoint.fill("+1 (415) 555-0100");
  await endpoint.blur();
  await expect(field("endpoint")).toHaveAttribute("data-invalid", "format");
  await field("endpoint").getByRole("button", { name: /\+14155550100/ }).click();
  await expect(endpoint).toHaveValue("+14155550100");

  // HTTPS: an http:// URL switches scheme.
  await input("protocol").selectOption("https");
  await endpoint.fill("http://example.com/hook");
  await endpoint.blur();
  await expect(field("endpoint")).toHaveAttribute("data-invalid", "pattern");
  await field("endpoint").getByRole("button", { name: /https:\/\/example.com\/hook/ }).click();
  await expect(endpoint).toHaveValue("https://example.com/hook");

  // Email: a misspelt common domain.
  await input("protocol").selectOption("email");
  await endpoint.fill("dev@gmial.com");
  await endpoint.blur();
  await field("endpoint").getByRole("button", { name: /dev@gmail.com/ }).click();
  await expect(endpoint).toHaveValue("dev@gmail.com");

  // A well-formed ARN of a queue that does not exist: the server's answer
  // lands on the endpoint, with the queue it probably meant.
  await input("protocol").selectOption("sqs");
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
