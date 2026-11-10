import { CreateGuardrailCommand, BedrockClient } from "@aws-sdk/client-bedrock";
import { CreateBucketCommand, S3Client } from "@aws-sdk/client-s3";
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
