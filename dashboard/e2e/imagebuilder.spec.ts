import { AddRoleToInstanceProfileCommand, CreateInstanceProfileCommand, CreateRoleCommand, IAMClient } from "@aws-sdk/client-iam";
import { expect, test } from "@playwright/test";

import { row, sdk, submit, submitInline, unique } from "./helpers";

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
  await submit(page, "create-infrastructure", { name: infra, profile: role });
  await expect(row(page, infra)).toContainText(role);

  const pipeline = unique("dash-pipe");
  await page.goto("/imagebuilder");
  await submit(page, "create-pipeline", { name: pipeline, recipe: `${recipe} 1.0.0`, infrastructure: infra });
  await expect(row(page, pipeline)).toContainText(recipe);
  await row(page, pipeline).getByRole("button", { name: `Run ${pipeline}` }).click();
  await page.goto("/imagebuilder?tab=images");
  await expect(row(page, recipe)).toBeVisible();
});
