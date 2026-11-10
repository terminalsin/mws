import { expect, test } from "@playwright/test";

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
