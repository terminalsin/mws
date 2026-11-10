import { AddRoleToInstanceProfileCommand, CreateInstanceProfileCommand, CreateRoleCommand, IAMClient } from "@aws-sdk/client-iam";
import {
  CreateComponentCommand,
  CreateImagePipelineCommand,
  CreateImageRecipeCommand,
  CreateInfrastructureConfigurationCommand,
  GetImagePipelineCommand,
  ImagebuilderClient,
  ListImagesCommand,
} from "@aws-sdk/client-imagebuilder";
import { expect, test, type Page } from "@playwright/test";

import { row, rowAction, sdk, submit, submitInline, unique } from "./helpers";

test("Image Builder: component, recipe, infrastructure and a pipeline run", async ({ page }) => {
  const component = unique("dash-comp");
  await page.goto("/imagebuilder?tab=components");
  await submit(page, "create-component", { name: component });
  await expect(row(page, component)).toContainText("build");

  const recipe = unique("dash-recipe");
  await page.goto("/imagebuilder?tab=recipes");
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
  await page.goto("/imagebuilder?tab=infrastructure");
  // A mistyped instance type gets the real one; a taken name the next free one.
  let sheet = await openSheet(page, "create-infrastructure");
  await sheet.locator('input[name="type"]').fill("m5.lrage");
  await sheet.locator('input[name="type"]').blur();
  await expect(field(sheet, "type")).toHaveAttribute("data-invalid", "enum");
  await field(sheet, "type").getByRole("button", { name: /Did you mean m5\.large/ }).click();
  await expect(sheet.locator('input[name="type"]')).toHaveValue("m5.large");
  await page.keyboard.press("Escape");
  await submit(page, "create-infrastructure", { name: infra, profile: role, type: "" });
  await expect(row(page, infra)).toContainText(role);
  sheet = await openSheet(page, "create-infrastructure");
  await sheet.locator('input[name="name"]').fill(infra);
  await sheet.locator('input[name="name"]').blur();
  await expect(field(sheet, "name")).toHaveAttribute("data-invalid", "taken");
  await expect(field(sheet, "name").getByRole("button", { name: /Use / })).toContainText(`${infra}-2`);
  await page.keyboard.press("Escape");

  const pipeline = unique("dash-pipe");
  await page.goto("/imagebuilder");
  // A Unix cron schedule is converted to AWS's six fields.
  sheet = await openSheet(page, "create-pipeline");
  await sheet.locator('input[name="cron"]').fill("0 9 * * 1-5");
  await sheet.locator('input[name="cron"]').blur();
  await expect(field(sheet, "cron")).toHaveAttribute("data-invalid", "format");
  await field(sheet, "cron").getByRole("button", { name: /Convert from Unix cron/ }).click();
  await expect(sheet.locator('input[name="cron"]')).toHaveValue("0 9 ? * MON-FRI *");
  await page.keyboard.press("Escape");
  await submit(page, "create-pipeline", { name: pipeline, recipe: `${recipe} 1.0.0`, infrastructure: infra, cron: "0 9 ? * MON-FRI *" });
  await expect(row(page, pipeline)).toContainText(recipe);
  await row(page, pipeline).getByRole("button", { name: `Run ${pipeline}` }).click();
  await page.goto("/imagebuilder?tab=images");
  await expect(row(page, recipe)).toBeVisible();
});

async function openSheet(page: Page, testId: string) {
  const form = page.locator("dialog[open]").getByTestId(testId).and(page.locator("form"));
  await expect(async () => {
    if (!(await form.isVisible())) await page.getByTestId(`${testId}-open`).first().click();
    await expect(form).toBeVisible({ timeout: 1000 });
  }).toPass();
  return form;
}

const field = (form: ReturnType<Page["locator"]>, name: string) => form.locator(".field").filter({ has: form.page().locator(`[name="${name}"]`) });

test("Image Builder: component fields repair names and versions", async ({ page }) => {
  const name = unique("dash_comp");
  await page.goto("/imagebuilder?tab=components");
  const form = await openSheet(page, "create-component");
  const input = form.locator('input[name="name"]');
  const version = form.locator('input[name="version"]');

  // An unsupported character is removed in one click.
  await input.fill(`${name}!`);
  await input.blur();
  await expect(field(form, "name")).toHaveAttribute("data-invalid", "pattern");
  await field(form, "name").getByRole("button", { name: /Remove unsupported/ }).click();
  await expect(input).toHaveValue(name);

  // A short version is completed to a semantic one.
  await version.fill("1.0");
  await version.blur();
  await expect(field(form, "version")).toHaveAttribute("data-invalid", "format");
  await field(form, "version").getByRole("button", { name: /semantic version/ }).click();
  await expect(version).toHaveValue("1.0.0");
  await form.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(row(page, name)).toContainText("1.0.0");

  // The same version again: MWS's conflict lands on the version, with the
  // next patch version as the fix.
  const again = await openSheet(page, "create-component");
  await again.locator('input[name="name"]').fill(name);
  await again.locator('button[type="submit"]').click();
  await expect(field(again, "version")).toHaveAttribute("data-invalid", "taken");
  await expect(again.locator(".result.error")).toHaveCount(0);
  await field(again, "version").getByRole("button", { name: /Use 1\.0\.1/ }).click();
  await again.locator('button[type="submit"]').click();
  await expect(page.locator("dialog[open]")).toHaveCount(0);

  // A broken document: MWS names the parameter, so the error shows on it.
  const broken = await openSheet(page, "create-component");
  await broken.locator('input[name="name"]').fill(unique("dash_comp"));
  await broken.locator('textarea[name="data"]').fill("name: x\nschemaVersion: 1.0\n");
  await broken.locator('button[type="submit"]').click();
  await expect(field(broken, "data")).toHaveAttribute("data-invalid", "server");
  await expect(broken.locator(".result.error")).toHaveCount(0);
});

test("Image Builder: disabling a pipeline keeps its settings, and a run opens the image", async ({ page }) => {
  const ib = new ImagebuilderClient(sdk);
  const iam = new IAMClient(sdk);
  const role = unique("dash-ibp");
  await iam.send(
    new CreateRoleCommand({
      RoleName: role,
      AssumeRolePolicyDocument: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" }] }),
    }),
  );
  await iam.send(new CreateInstanceProfileCommand({ InstanceProfileName: role }));
  await iam.send(new AddRoleToInstanceProfileCommand({ InstanceProfileName: role, RoleName: role }));
  const component = await ib.send(
    new CreateComponentCommand({
      name: unique("dash-pc"),
      semanticVersion: "1.0.0",
      platform: "Linux",
      data: "name: hello\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps:\n      - name: Hello\n        action: ExecuteBash\n        inputs:\n          commands:\n            - echo hello\n",
    }),
  );
  const parent = (await ib.send(new ListImagesCommand({ owner: "Amazon" }))).imageVersionList?.find((i) => i.platform === "Linux")?.arn;
  const recipe = await ib.send(
    new CreateImageRecipeCommand({ name: unique("dash-pr"), semanticVersion: "1.0.0", parentImage: parent ?? "ami-0123456789abcdef0", components: [{ componentArn: component.componentBuildVersionArn }] }),
  );
  const infra = await ib.send(new CreateInfrastructureConfigurationCommand({ name: unique("dash-pi"), instanceProfileName: role }));
  const name = unique("dash-pipe");
  const created = await ib.send(
    new CreateImagePipelineCommand({
      name,
      imageRecipeArn: recipe.imageRecipeArn,
      infrastructureConfigurationArn: infra.infrastructureConfigurationArn,
      schedule: { scheduleExpression: "cron(0 9 ? * MON-FRI *)" },
      imageScanningConfiguration: { imageScanningEnabled: true },
      enhancedImageMetadataEnabled: false,
    }),
  );
  const arn = created.imagePipelineArn!;

  await page.goto(`/imagebuilder/pipeline?arn=${encodeURIComponent(arn)}`);
  await expect(page.getByRole("heading", { name })).toBeVisible();
  await page.getByTestId("toggle-pipeline").locator('button[type="submit"]').click();
  await expect(page.locator(".status").filter({ hasText: /^disabled$/ })).toBeVisible();
  const after = (await ib.send(new GetImagePipelineCommand({ imagePipelineArn: arn }))).imagePipeline!;
  expect(after.status).toBe("DISABLED");
  expect(after.schedule?.scheduleExpression).toBe("cron(0 9 ? * MON-FRI *)");
  expect(after.imageScanningConfiguration?.imageScanningEnabled).toBe(true);
  expect(after.enhancedImageMetadataEnabled).toBe(false);
  await page.getByTestId("toggle-pipeline").locator('button[type="submit"]').click();
  await expect(page.locator(".status").filter({ hasText: /^enabled$/ })).toBeVisible();

  // A run lands on the new image, which links back to its pipeline.
  await page.getByTestId("run-pipeline").locator('button[type="submit"]').click();
  await page.waitForURL(/\/imagebuilder\/image\?arn=/);
  await expect(page.locator(`a[href="/imagebuilder/pipeline?arn=${encodeURIComponent(arn)}"]`)).toBeVisible();
  await expect(page.getByRole("link", { name: "Output resources" })).toBeVisible();
  await page.goto(`/imagebuilder/pipeline?arn=${encodeURIComponent(arn)}`);
  await expect(page.getByLabel("Output images").locator("li.row")).toHaveCount(1);
});

test("Image Builder: distribution settings and workflows are created and deleted", async ({ page }) => {
  const dist = unique("dash-dist");
  await page.goto("/imagebuilder?tab=distribution");
  await submit(page, "create-distribution", { name: dist, amiName: "dash-{{ imagebuilder:buildDate }}" });
  await expect(row(page, dist)).toContainText(sdk.region);
  await rowAction(page, dist, `Delete ${dist}`);
  await expect(row(page, dist)).toHaveCount(0);

  const wf = unique("dash-wf");
  await page.goto("/imagebuilder?tab=workflows");
  await submit(page, "create-workflow", { name: wf });
  await expect(row(page, wf)).toContainText("build");
  await rowAction(page, wf, `Delete ${wf}`);
  await expect(row(page, wf)).toHaveCount(0);
});
