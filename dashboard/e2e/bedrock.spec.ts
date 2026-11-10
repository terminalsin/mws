import {
  BedrockClient,
  CreateGuardrailCommand,
  GetModelInvocationLoggingConfigurationCommand,
  PutModelInvocationLoggingConfigurationCommand,
} from "@aws-sdk/client-bedrock";
import { CreateBucketCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { expect, test, type Page } from "@playwright/test";

import { row, rowAction, sdk, submit, submitInline, unique } from "./helpers";

test("Bedrock: chat in the playground", async ({ page }) => {
  await page.goto("/bedrock/playground");
  const status = await submitInline(page, "converse", { prompt: "hello from the dashboard" });
  await expect(status).toHaveClass(/ok/);
  await expect(status).toContainText("tokens");
  await expect(status.locator("pre")).toContainText("hello from the dashboard");
});

test("Bedrock: a guardrail blocks a denied word", async ({ page }) => {
  const name = unique("dash-guard");
  await page.goto("/bedrock/guardrails");
  await submit(page, "create-guardrail", { name, words: "pineapple" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const blocked = await submitInline(page, "test-guardrail", { text: "I love pineapple pizza" });
  await expect(blocked).toContainText("Intervened");
  await expect(blocked).toContainText("word: pineapple");
  const passed = await submitInline(page, "test-guardrail", { text: "I love pizza" });
  await expect(passed).toContainText("Passed");
});

test("Bedrock: the model catalog groups models by provider", async ({ page }) => {
  await page.goto("/bedrock");
  await expect(page.getByRole("heading", { level: 2, name: "Anthropic" })).toBeVisible();
  await page.getByRole("link", { name: /^Embeddings/ }).click();
  await expect(page.getByText("amazon.titan-embed-text-v2:0")).toBeVisible();
});

test("Bedrock: store a model provider", async ({ page, request }) => {
  const name = unique("dash-llm").toLowerCase();
  await page.goto("/bedrock/settings");
  await submit(page, "add-provider", { name, url: "http://127.0.0.1:9/v1", apiKey: "sk-dash-secret-9999", models: "dashtest.*", model: "tiny" });
  const r = row(page, name);
  await expect(r).toContainText("sk-…9999");
  await expect(r).toContainText("dashtest.*");
  await expect(r).not.toContainText("sk-dash-secret");
  const route = await request.get(`${sdk.endpoint}/_aws/bedrock/providers/route?modelId=dashtest.anything`);
  expect(await route.json()).toMatchObject({ provider: name, upstreamModel: "tiny" });
  await rowAction(page, name, `Delete ${name}`);
  await expect(row(page, name)).toHaveCount(0);
});

test("Bedrock: a preset fills in the provider, local CLIs included", async ({ page, request }) => {
  await page.goto("/bedrock/settings");
  const { form, control } = await sheet(page, "add-provider");
  // A cloud preset: its URL and upstream model, the key is all that is asked.
  await form.getByTestId("preset-groq").click();
  await expect(form.getByTestId("preset-groq")).toHaveAttribute("aria-checked", "true");
  await expect(control("kind")).toHaveValue("openai");
  await expect(control("model")).toHaveValue("llama-3.3-70b-versatile");
  await expect(control("apiKey")).toBeVisible();
  await expect(control("url")).toBeHidden();
  // A CLI preset: the command, no URL or key.
  await form.getByTestId("preset-codex").click();
  const name = await control("name").inputValue();
  expect(name).toMatch(/^codex(-\d+)?$/);
  await expect(control("kind")).toHaveValue("codex");
  await expect(control("command")).toHaveValue("codex");
  await expect(control("apiKey")).toHaveCount(0);
  await control("models").fill(`dashcli${Date.now()}.*`);
  const models = await control("models").inputValue();
  await form.locator('button[type="submit"]').click();
  await expect(form).toBeHidden();
  const r = row(page, name);
  await expect(r.locator('img[src="/icons/ai/codex.svg"]')).toBeVisible();
  const route = await request.get(`${sdk.endpoint}/_aws/bedrock/providers/route?modelId=${models.replace("*", "x")}`);
  expect(await route.json()).toMatchObject({ provider: name, kind: "codex" });
  await rowAction(page, name, `Delete ${name}`);
  await expect(row(page, name)).toHaveCount(0);
});

/** Open the sheet `testId` and return a way to reach its fields by name. */
async function sheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  const field = (name: string) => form.locator(".field").filter({ has: page.locator(`[name="${name}"]`) });
  const control = (name: string) => form.locator(`[name="${name}"]`);
  return { form, field, control };
}

test("Bedrock validation: guardrail names are repaired in place, taken ones get the next free name", async ({ page }) => {
  const taken = unique("dash-guard");
  await new BedrockClient(sdk).send(
    new CreateGuardrailCommand({ name: taken, blockedInputMessaging: "no", blockedOutputsMessaging: "no", wordPolicyConfig: { wordsConfig: [{ text: "x" }] } }),
  );
  await page.goto("/bedrock/guardrails");
  const { field, control } = await sheet(page, "create-guardrail");

  await control("name").fill("Support bot guard");
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /Replace spaces/ }).click();
  await expect(control("name")).toHaveValue("Support-bot-guard");
  await expect(field("name")).not.toHaveAttribute("data-invalid");

  await control("name").fill(taken);
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "taken");
  await field("name").getByRole("button", { name: /Use / }).click();
  await expect(control("name")).toHaveValue(`${taken}-2`);
});

test("Bedrock validation: provider fields fix URLs, JSON and key=value lists", async ({ page }) => {
  await page.goto("/bedrock/settings");
  const { form, field, control } = await sheet(page, "add-provider");

  await control("name").fill("Ollama");
  await control("name").blur();
  await expect(field("name")).toHaveAttribute("data-invalid", "pattern");
  await field("name").getByRole("button", { name: /Lowercase/ }).click();
  await expect(control("name")).toHaveValue("ollama");

  await control("url").fill("127.0.0.1:11434/v1");
  await control("url").blur();
  await expect(field("url")).toHaveAttribute("data-invalid", "format");
  await field("url").getByRole("button", { name: /Add http:\/\// }).click();
  await expect(control("url")).toHaveValue("http://127.0.0.1:11434/v1");

  await control("params").fill("{temperature: 0.2,}");
  await control("params").blur();
  await expect(field("params")).toHaveAttribute("data-invalid", "format");
  await field("params").getByRole("button", { name: /Fix the JSON/ }).click();
  await expect(control("params")).toHaveValue('{\n  "temperature": 0.2\n}');

  await control("headers").fill("x-team: ml");
  await control("headers").blur();
  await expect(field("headers")).toHaveAttribute("data-invalid", "format");
  await field("headers").getByRole("button", { name: /Rewrite as key=value/ }).click();
  await expect(control("headers")).toHaveValue("x-team=ml");
  await expect(form.locator(".field[data-invalid]")).toHaveCount(0);
});

test("Bedrock validation: a logging bucket that does not exist suggests the one you meant", async ({ page }) => {
  const bucket = unique("dash-logs").toLowerCase();
  await new S3Client({ ...sdk, forcePathStyle: true }).send(new CreateBucketCommand({ Bucket: bucket }));
  await page.goto("/bedrock/settings");
  const { form, field, control } = await sheet(page, "edit-logging");
  const typo = bucket.replace("dash-logs", "dash-lgos");
  await control("bucket").fill(typo);
  await form.locator('button[type="submit"]').click();
  await expect(field("bucket")).toHaveAttribute("data-invalid", "missing");
  await expect(form.locator(".result.error")).toHaveCount(0);
  await field("bucket").getByRole("button", { name: /Did you mean/ }).click();
  await expect(control("bucket")).toHaveValue(bucket);
});

test("Bedrock: customize a model, then buy, rename and delete its Provisioned Throughput", async ({ page }) => {
  const bucket = unique("dash-tune").toLowerCase();
  await new S3Client({ ...sdk, forcePathStyle: true }).send(new CreateBucketCommand({ Bucket: bucket }));
  const job = unique("dash-job");
  const model = unique("dashmodel").replace(/-/g, "_");
  await page.goto("/bedrock/custom-models");
  await submit(page, "create-customization", { jobName: job, modelName: model, training: `s3://${bucket}/train.jsonl`, output: `s3://${bucket}/out/` });
  await expect(page.getByRole("heading", { level: 1, name: job })).toBeVisible();
  await expect(page.getByRole("link", { name: `s3://${bucket}/train.jsonl` })).toBeVisible();
  await expect(page.getByText("Completed")).toBeVisible({ timeout: 30_000 });
  await page.getByRole("link", { name: model }).click();
  await expect(page.getByRole("heading", { level: 1, name: model })).toBeVisible();
  await expect(page.getByRole("link", { name: job })).toBeVisible();
  await expect(page.getByRole("link", { name: "Purchase Provisioned Throughput" })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("link", { name: "Purchase Provisioned Throughput" }).click();
  const pt = unique("dash-pt");
  await submit(page, "create-provisioned", { name: pt, units: "1" });
  await expect(page.getByRole("heading", { level: 1, name: pt })).toBeVisible();
  await expect(page.getByText("InService")).toBeVisible({ timeout: 30_000 });
  await submit(page, "edit-provisioned", { name: `${pt}-x` });
  await expect(page.getByRole("heading", { level: 1, name: `${pt}-x` })).toBeVisible();
  page.once("dialog", (d) => d.accept().catch(() => {}));
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page).toHaveURL(/\/bedrock\/provisioned$/);
  await expect(row(page, `${pt}-x`)).toHaveCount(0);
});

test("Bedrock: a batch inference job runs over S3 records", async ({ page }) => {
  const bucket = unique("dash-batch").toLowerCase();
  const s3 = new S3Client({ ...sdk, forcePathStyle: true });
  await s3.send(new CreateBucketCommand({ Bucket: bucket }));
  const record = { recordId: "r1", modelInput: { anthropic_version: "bedrock-2023-05-31", max_tokens: 50, messages: [{ role: "user", content: "hi" }] } };
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: "in/records.jsonl", Body: JSON.stringify(record) + "\n" }));
  const job = unique("dash-batch");
  await page.goto("/bedrock/batch");
  await submit(page, "create-batch", { jobName: job, input: `s3://${bucket}/in/records.jsonl`, output: `s3://${bucket}/out/` });
  await expect(page.getByRole("heading", { level: 1, name: job })).toBeVisible();
  await expect(page.getByText(/^(Completed|PartiallyCompleted|Failed)$/)).toBeVisible({ timeout: 40_000 });
  await page.getByRole("link", { name: "Batch inference" }).first().click();
  await expect(row(page, job)).toBeVisible();
});

test("Bedrock: start an async invocation and open it", async ({ page }) => {
  const bucket = unique("dash-async").toLowerCase();
  await new S3Client({ ...sdk, forcePathStyle: true }).send(new CreateBucketCommand({ Bucket: bucket }));
  await page.goto("/bedrock/async");
  await submit(page, "start-async", { output: `s3://${bucket}/videos/` });
  await expect(page.getByRole("link", { name: new RegExp(`s3://${bucket}/videos/`) })).toBeVisible();
  await expect(page.getByText(/^(InProgress|Completed|Failed)$/)).toBeVisible();
});

test("Bedrock: edit a guardrail's word filter and test the draft", async ({ page }) => {
  const name = unique("dash-guard-edit");
  await page.goto("/bedrock/guardrails");
  await submit(page, "create-guardrail", { name, words: "pineapple", description: "edits" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await submit(page, "edit-guardrail", { words: "anchovy", regexes: "Order: ORD-[0-9]{6}", grounding: "0.5" });
  await expect(page.getByRole("heading", { level: 2, name: /Contextual grounding/ })).toBeVisible();
  const blocked = await submitInline(page, "test-guardrail", { text: "Extra anchovy please" });
  await expect(blocked).toContainText("Intervened");
  const passed = await submitInline(page, "test-guardrail", { text: "Extra pineapple please" });
  await expect(passed).toContainText("Passed");
});

test("Bedrock: saving the logging sheet keeps an S3-only configuration as it was", async ({ page }) => {
  const bucket = unique("dash-invlogs").toLowerCase();
  await new S3Client({ ...sdk, forcePathStyle: true }).send(new CreateBucketCommand({ Bucket: bucket }));
  const client = new BedrockClient(sdk);
  await client.send(
    new PutModelInvocationLoggingConfigurationCommand({
      loggingConfig: { s3Config: { bucketName: bucket, keyPrefix: "logs" }, textDataDeliveryEnabled: false, videoDataDeliveryEnabled: true, imageDataDeliveryEnabled: true, embeddingDataDeliveryEnabled: false },
    }),
  );
  await page.goto("/bedrock/settings");
  await submit(page, "edit-logging");
  const after = (await client.send(new GetModelInvocationLoggingConfigurationCommand({}))).loggingConfig;
  expect(after?.cloudWatchConfig).toBeUndefined();
  expect(after).toMatchObject({ s3Config: { bucketName: bucket, keyPrefix: "logs" }, textDataDeliveryEnabled: false, videoDataDeliveryEnabled: true, imageDataDeliveryEnabled: true, embeddingDataDeliveryEnabled: false });
});

test("Bedrock: an application inference profile has its own page with tags", async ({ page }) => {
  const name = unique("dash-profile");
  await page.goto("/bedrock/profiles?tab=application");
  await submit(page, "create-profile", { name, description: "team profile", tags: "CostCenter=ml" });
  await row(page, name).getByRole("link").first().click();
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.getByText("team profile")).toBeVisible();
  await expect(page.locator(".tag").filter({ hasText: "CostCenter" })).toBeVisible();
  await submit(page, "manage-tags", { tags: "CostCenter=ml\nteam=search" });
  await expect(page.locator(".tag").filter({ hasText: "team" })).toContainText("search");
  await expect(page.getByRole("link", { name: "Open in playground" })).toHaveAttribute("href", /inference-profile/);
});
