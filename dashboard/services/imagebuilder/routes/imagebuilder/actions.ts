"use server";

import {
  CreateComponentCommand,
  CreateImagePipelineCommand,
  CreateImageRecipeCommand,
  CreateInfrastructureConfigurationCommand,
  DeleteComponentCommand,
  DeleteImagePipelineCommand,
  DeleteImageRecipeCommand,
  DeleteInfrastructureConfigurationCommand,
  GetImagePipelineCommand,
  ListInfrastructureConfigurationsCommand,
  ListComponentBuildVersionsCommand,
  StartImagePipelineExecutionCommand,
  UpdateImagePipelineCommand,
  type Platform,
} from "@aws-sdk/client-imagebuilder";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { ROLES, ensureRole, wantsAuto } from "@mws-dashboard/aws/auto";
import { randomUUID } from "node:crypto";

import { imagebuilder } from "../../lib/clients";

const path = "/imagebuilder";

export async function createComponent(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await imagebuilder()).send(
      new CreateComponentCommand({
        name: required(form, "name", "Name"),
        semanticVersion: text(form, "version") || "1.0.0",
        platform: (text(form, "platform") || "Linux") as Platform,
        data: required(form, "data", "Document"),
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, path);
}

export async function createRecipe(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const components = form.getAll("component").map(String);
    if (!components.length) throw new Error("Choose at least one component");
    await (await imagebuilder()).send(
      new CreateImageRecipeCommand({
        name: required(form, "name", "Name"),
        semanticVersion: text(form, "version") || "1.0.0",
        parentImage: required(form, "parent", "Base image"),
        components: components.map((componentArn) => ({ componentArn })),
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, path);
}

export async function createInfrastructure(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await imagebuilder()).send(
      new CreateInfrastructureConfigurationCommand({
        name: required(form, "name", "Name"),
        instanceProfileName: required(form, "profile", "Instance profile"),
        instanceTypes: text(form, "type") ? [text(form, "type")] : undefined,
        terminateInstanceOnFailure: true,
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, path);
}

/** The picked infrastructure configuration, or a default one (with the
 * instance profile Image Builder needs) when "create automatically" is picked. */
async function infrastructureFrom(form: FormData): Promise<string> {
  if (!wantsAuto(form, "infrastructure")) return text(form, "infrastructure");
  const client = await imagebuilder();
  const existing = (await client.send(new ListInfrastructureConfigurationsCommand({}))).infrastructureConfigurationSummaryList ?? [];
  const found = existing.find((i) => i.name === "default");
  if (found?.arn) return found.arn;
  await ensureRole(ROLES.imageBuilderInstance);
  const out = await client.send(
    new CreateInfrastructureConfigurationCommand({ name: "default", instanceProfileName: ROLES.imageBuilderInstance.name, terminateInstanceOnFailure: true, clientToken: randomUUID() }),
  );
  return out.infrastructureConfigurationArn!;
}

export async function createPipeline(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const cron = text(form, "cron");
    await (await imagebuilder()).send(
      new CreateImagePipelineCommand({
        name: required(form, "name", "Name"),
        imageRecipeArn: required(form, "recipe", "Recipe"),
        infrastructureConfigurationArn: await infrastructureFrom(form),
        schedule: cron ? { scheduleExpression: `cron(${cron})`, pipelineExecutionStartCondition: "EXPRESSION_MATCH_ONLY" } : undefined,
        imageTestsConfiguration: { imageTestsEnabled: text(form, "tests") === "on" },
        status: "ENABLED",
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, path);
}

export async function runPipeline(arn: string) {
  return act(async () => {
    const out = await (await imagebuilder()).send(new StartImagePipelineExecutionCommand({ imagePipelineArn: arn, clientToken: randomUUID() }));
    return `Building ${out.imageBuildVersionArn?.split("/").slice(-2).join("/")}`;
  }, path);
}

export async function setPipelineEnabled(arn: string, enabled: boolean) {
  return act(async () => {
    const client = await imagebuilder();
    const p = (await client.send(new GetImagePipelineCommand({ imagePipelineArn: arn }))).imagePipeline!;
    await client.send(
      new UpdateImagePipelineCommand({
        imagePipelineArn: arn,
        imageRecipeArn: p.imageRecipeArn,
        containerRecipeArn: p.containerRecipeArn,
        infrastructureConfigurationArn: p.infrastructureConfigurationArn,
        distributionConfigurationArn: p.distributionConfigurationArn,
        imageTestsConfiguration: p.imageTestsConfiguration,
        schedule: p.schedule,
        description: p.description,
        status: enabled ? "ENABLED" : "DISABLED",
        clientToken: randomUUID(),
      }),
    );
    return enabled ? "Enabled" : "Disabled";
  }, path);
}

export async function deleteResource(kind: "pipeline" | "recipe" | "component" | "infrastructure", arn: string) {
  return act(async () => {
    const client = await imagebuilder();
    if (kind === "pipeline") await client.send(new DeleteImagePipelineCommand({ imagePipelineArn: arn }));
    if (kind === "recipe") await client.send(new DeleteImageRecipeCommand({ imageRecipeArn: arn }));
    if (kind === "component") {
      // The list shows versions; deleting takes each build of the version.
      const builds = (await client.send(new ListComponentBuildVersionsCommand({ componentVersionArn: arn }))).componentSummaryList ?? [];
      for (const b of builds) await client.send(new DeleteComponentCommand({ componentBuildVersionArn: b.arn }));
    }
    if (kind === "infrastructure") await client.send(new DeleteInfrastructureConfigurationCommand({ infrastructureConfigurationArn: arn }));
    return "Deleted";
  }, path);
}
