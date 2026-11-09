import { AddRoleToInstanceProfileCommand, CreateInstanceProfileCommand, CreateRoleCommand, IAMClient } from "@aws-sdk/client-iam";
import { expect, test, type Page } from "@playwright/test";

import { row, rowAction, sdk, submit, unique } from "./helpers";

/** Fill a form that is on the page (not in a sheet) and return its result line. */
async function run(page: Page, testId: string, fields: Record<string, string>) {
  const form = page.getByTestId(testId).and(page.locator("form"));
  for (const [name, value] of Object.entries(fields)) await form.locator(`[name="${name}"]`).fill(value);
  await form.locator('button[type="submit"]').click();
  const status = form.getByRole("status");
  await expect(status).toBeVisible();
  return status;
}

test("Bedrock: chat in the playground", async ({ page }) => {
  await page.goto("/platform/bedrock/playground");
  const status = await run(page, "converse", { prompt: "hello from the dashboard" });
  await expect(status).toHaveClass(/ok/);
  await expect(status).toContainText("tokens");
  await expect(status.locator("pre")).toContainText("hello from the dashboard");
});

test("Bedrock: a guardrail blocks a denied word", async ({ page }) => {
  const name = unique("dash-guard");
  await page.goto("/platform/bedrock/guardrails");
  await submit(page, "create-guardrail", { name, words: "pineapple" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const blocked = await run(page, "test-guardrail", { text: "I love pineapple pizza" });
  await expect(blocked).toContainText("Intervened");
  await expect(blocked).toContainText("word: pineapple");
  const passed = await run(page, "test-guardrail", { text: "I love pizza" });
  await expect(passed).toContainText("Passed");
});

test("Bedrock: the model catalog groups models by provider", async ({ page }) => {
  await page.goto("/platform/bedrock");
  await expect(page.getByRole("heading", { level: 2, name: "Anthropic" })).toBeVisible();
  await page.getByRole("link", { name: /^Embeddings/ }).click();
  await expect(page.getByText("amazon.titan-embed-text-v2:0")).toBeVisible();
});

test("Bedrock: store a model provider", async ({ page, request }) => {
  const name = unique("dash-llm").toLowerCase();
  await page.goto("/platform/bedrock/settings");
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

test("Amplify: deploy a site to a branch", async ({ page, request }) => {
  const name = unique("dash-site");
  await page.goto("/platform/amplify");
  await submit(page, "create-app", { name, branch: "main" });
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  const appId = new URL(page.url()).searchParams.get("id")!;
  await row(page, "main").getByRole("link").first().click();
  await submit(page, "deploy", { html: `<h1>${name}</h1>` });
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Deployments").locator("li.row").first()).toContainText("succeed", { timeout: 1000 });
  }).toPass();
  const site = await request.get(`${sdk.endpoint}/_aws/amplify/sites/${appId}/main/`);
  expect(await site.text()).toContain(name);
});

test("CodeArtifact: a repository with an npm upstream and its connection instructions", async ({ page }) => {
  const domain = unique("dash").toLowerCase().slice(0, 40);
  const repo = unique("dash-npm");
  await page.goto("/platform/codeartifact?tab=domains");
  await submit(page, "create-domain", { name: domain });
  await expect(row(page, domain)).toBeVisible();
  await page.goto("/platform/codeartifact");
  await submit(page, "create-repository", { name: repo, domain, external: "public:npmjs" });
  await expect(page.getByRole("heading", { level: 1, name: repo })).toBeVisible();
  await expect(page.locator(".specs")).toContainText("npmjs");
  await expect(page.locator("pre.code")).toContainText("npm config set registry");
  await expect(page.locator("pre.code")).toContainText(`/${domain}-`);
});

test("Image Builder: component, recipe, infrastructure and a pipeline run", async ({ page }) => {
  const component = unique("dash-comp");
  await page.goto("/platform/imagebuilder?tab=components");
  await submit(page, "create-component", { name: component });
  await expect(row(page, component)).toContainText("build");

  const recipe = unique("dash-recipe");
  await page.goto("/platform/imagebuilder?tab=recipes");
  await submit(page, "create-recipe", { name: recipe });
  await expect(row(page, recipe)).toContainText("1.0.0");

  const iam = new IAMClient(sdk);
  const role = unique("dash-ib");
  await iam.send(
    new CreateRoleCommand({
      RoleName: role,
      AssumeRolePolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }] }),
    }),
  );
  await iam.send(new CreateInstanceProfileCommand({ InstanceProfileName: role }));
  await iam.send(new AddRoleToInstanceProfileCommand({ InstanceProfileName: role, RoleName: role }));
  const infra = unique("dash-infra");
  await page.goto("/platform/imagebuilder?tab=infrastructure");
  await submit(page, "create-infrastructure", { name: infra, profile: role });
  await expect(row(page, infra)).toContainText(role);

  const pipeline = unique("dash-pipe");
  await page.goto("/platform/imagebuilder");
  await submit(page, "create-pipeline", { name: pipeline, recipe: `${recipe} 1.0.0`, infrastructure: infra });
  await expect(row(page, pipeline)).toContainText(recipe);
  await row(page, pipeline).getByRole("button", { name: `Run ${pipeline}` }).click();
  await page.goto("/platform/imagebuilder?tab=images");
  await expect(row(page, recipe)).toBeVisible();
});

test("Auto Scaling: a group launches its desired capacity", async ({ page }) => {
  const template = unique("dash-lt");
  const group = unique("dash-asg");
  await page.goto("/platform/autoscaling");
  await submit(page, "create-launch-template", { name: template });
  await submit(page, "create-group", { name: group, template, min: "0", desired: "1", max: "3" });
  await expect(page.getByRole("heading", { level: 1, name: group })).toBeVisible();
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Instances").locator("li.row")).toHaveCount(1, { timeout: 1000 });
  }).toPass();
  await page.getByRole("button", { name: "Scale out" }).click();
  await expect(async () => {
    await page.reload();
    await expect(page.getByLabel("Instances").locator("li.row")).toHaveCount(2, { timeout: 1000 });
  }).toPass();
  await page.getByRole("link", { name: /^Activity/ }).click();
  await expect(page.getByLabel("Activity").locator("li.row").first()).toContainText(/Launching/);
});

test("Marketplace: subscribe a buyer and meter usage", async ({ page }) => {
  const title = unique("Dash SaaS");
  await page.goto("/platform/marketplace");
  await submit(page, "create-product", { title, dimensions: "users requests" });
  await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
  const subscribed = await submit(page, "subscribe", { account: "111122223333", "dim:users": "10" });
  await expect(subscribed).toContainText("x-amzn-marketplace-token");
  await page.reload();
  await expect(row(page, "111122223333")).toContainText("users 10");
  await submit(page, "meter", { dimension: "users", quantity: "7" });
  await page.reload();
  await expect(page.getByLabel("Usage by dimension")).toContainText("7");
  await page.goto("/platform/marketplace?tab=records");
  await expect(page.locator("li.row").filter({ hasText: title }).first()).toContainText("7 × users");
});

test("AI and developer tools: every list page renders", async ({ page }) => {
  for (const [path, heading] of [
    ["/platform/bedrock/profiles", "Inference profiles"],
    ["/platform/bedrock/profiles?tab=application", "Inference profiles"],
    ["/platform/bedrock/settings", "Settings"],
    ["/platform/codeartifact?tab=domains", "Domains"],
    ["/platform/imagebuilder?tab=images", "Images"],
    ["/platform/autoscaling", "Auto Scaling groups"],
  ]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
    await expect(page.locator(".banner.error")).toHaveCount(0);
  }
});
