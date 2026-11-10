"use server";

import {
  CancelImageCreationCommand,
  CreateComponentCommand,
  CreateContainerRecipeCommand,
  CreateDistributionConfigurationCommand,
  CreateLifecyclePolicyCommand,
  CreateWorkflowCommand,
  DeleteContainerRecipeCommand,
  DeleteDistributionConfigurationCommand,
  DeleteImageCommand,
  DeleteLifecyclePolicyCommand,
  DeleteWorkflowCommand,
  ListWorkflowBuildVersionsCommand,
  RetryImageCommand,
  SendWorkflowStepActionCommand,
  StartResourceStateUpdateCommand,
  UpdateInfrastructureConfigurationCommand,
  type ResourceStatus,
  type WorkflowType,
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
import { act, all, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";
import { ROLES, ensureRole, roleFrom, wantsAuto } from "@mws-dashboard/aws/auto";
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
        workingDirectory: text(form, "workdir") || undefined,
        additionalInstanceConfiguration: text(form, "userData") ? { userDataOverride: Buffer.from(text(form, "userData")).toString("base64") } : undefined,
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, { revalidate: [path], fields: { parentImage: "parent", workingDirectory: "workdir", userDataOverride: "userData", semanticVersion: "version", name: "name" } });
}

export async function createInfrastructure(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await imagebuilder()).send(
      new CreateInfrastructureConfigurationCommand({
        name: required(form, "name", "Name"),
        instanceProfileName: required(form, "profile", "Instance profile"),
        ...infrastructureOptions(form),
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, { revalidate: [path], fields: INFRA_FIELDS });
}

const INFRA_FIELDS = { instanceTypes: "type", subnetId: "subnet", securityGroupIds: "groups", keyPair: "keyPair", snsTopicArn: "topic", "logging.s3Logs.s3BucketName": "logBucket", instanceProfileName: "profile" };
const words = (form: FormData, name: string) =>
  text(form, name)
    .split(/[\s,]+/)
    .filter(Boolean);

/** The infrastructure settings both create and edit send. */
function infrastructureOptions(form: FormData) {
  const types = words(form, "type");
  const groups = words(form, "groups");
  const bucket = text(form, "logBucket");
  return {
    description: text(form, "description") || undefined,
    instanceTypes: types.length ? types : undefined,
    subnetId: text(form, "subnet") || undefined,
    securityGroupIds: groups.length ? groups : undefined,
    keyPair: text(form, "keyPair") || undefined,
    snsTopicArn: text(form, "topic") || undefined,
    logging: bucket ? { s3Logs: { s3BucketName: bucket, s3KeyPrefix: text(form, "logPrefix") || undefined } } : undefined,
    instanceMetadataOptions: { httpTokens: text(form, "imds") || "required" },
    terminateInstanceOnFailure: form.get("keep") !== "on",
  };
}

export async function updateInfrastructure(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await imagebuilder();
    await client.send(
      new UpdateInfrastructureConfigurationCommand({
        infrastructureConfigurationArn: arn,
        instanceProfileName: required(form, "profile", "Instance profile"),
        ...infrastructureOptions(form),
        clientToken: randomUUID(),
      }),
    );
    return "Saved";
  }, { revalidate: [path], fields: INFRA_FIELDS });
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
        ...(required(form, "recipe", "Recipe").includes(":container-recipe/") ? { containerRecipeArn: text(form, "recipe") } : { imageRecipeArn: text(form, "recipe") }),
        infrastructureConfigurationArn: await infrastructureFrom(form),
        schedule: cron ? { scheduleExpression: `cron(${cron})`, pipelineExecutionStartCondition: "EXPRESSION_MATCH_ONLY" } : undefined,
        distributionConfigurationArn: text(form, "distribution") || undefined,
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
    redirect(`/imagebuilder/image?arn=${encodeURIComponent(out.imageBuildVersionArn!)}`);
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
        enhancedImageMetadataEnabled: p.enhancedImageMetadataEnabled,
        imageScanningConfiguration: p.imageScanningConfiguration,
        workflows: p.workflows,
        executionRole: p.executionRole,
        loggingConfiguration: p.loggingConfiguration,
        imageTags: p.imageTags,
        schedule: p.schedule,
        description: p.description,
        status: enabled ? "ENABLED" : "DISABLED",
        clientToken: randomUUID(),
      }),
    );
    return enabled ? "Enabled" : "Disabled";
  }, path);
}

export type Kind = "pipeline" | "recipe" | "component" | "infrastructure" | "container" | "distribution" | "workflow" | "lifecycle" | "image";

export async function deleteResource(kind: Kind, arn: string) {
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
    if (kind === "container") await client.send(new DeleteContainerRecipeCommand({ containerRecipeArn: arn }));
    if (kind === "distribution") await client.send(new DeleteDistributionConfigurationCommand({ distributionConfigurationArn: arn }));
    if (kind === "lifecycle") await client.send(new DeleteLifecyclePolicyCommand({ lifecyclePolicyArn: arn }));
    if (kind === "workflow") {
      const builds = await all(
        (nextToken) => client.send(new ListWorkflowBuildVersionsCommand({ workflowVersionArn: arn, nextToken })),
        (r) => r.workflowSummaryList,
        (r) => r.nextToken,
      );
      for (const b of builds) await client.send(new DeleteWorkflowCommand({ workflowBuildVersionArn: b.arn }));
    }
    if (kind === "image") {
      await client.send(new DeleteImageCommand({ imageBuildVersionArn: arn }));
      redirect("/imagebuilder?tab=images");
    }
    return "Deleted";
  }, path);
}

export async function cancelImage(arn: string) {
  return act(async () => {
    await (await imagebuilder()).send(new CancelImageCreationCommand({ imageBuildVersionArn: arn, clientToken: randomUUID() }));
    return "Cancelling";
  }, "/imagebuilder/image");
}

export async function retryImage(arn: string) {
  return act(async () => {
    const r = await (await imagebuilder()).send(new RetryImageCommand({ imageBuildVersionArn: arn, clientToken: randomUUID() }));
    redirect(`/imagebuilder/image?arn=${encodeURIComponent(r.imageBuildVersionArn ?? arn)}`);
  });
}

/** Deprecate, disable or delete an image (and what it made) on AWS's lifecycle path. */
export async function setImageState(arn: string, status: ResourceStatus) {
  return act(async () => {
    await (await imagebuilder()).send(new StartResourceStateUpdateCommand({ resourceArn: arn, state: { status }, clientToken: randomUUID() }));
    return `Marking ${status.toLowerCase()}`;
  }, "/imagebuilder/image");
}

export async function workflowStepAction(stepExecutionId: string, imageBuildVersionArn: string, action: "RESUME" | "STOP") {
  return act(async () => {
    await (await imagebuilder()).send(new SendWorkflowStepActionCommand({ stepExecutionId, imageBuildVersionArn, action, clientToken: randomUUID() }));
    return action === "RESUME" ? "Resumed" : "Stopped";
  }, "/imagebuilder/image");
}

export async function createDistribution(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const regions = words(form, "regions");
    if (!regions.length) regions.push(await region());
    const accounts = words(form, "accounts");
    const amiName = text(form, "amiName");
    await (await imagebuilder()).send(
      new CreateDistributionConfigurationCommand({
        name: required(form, "name", "Name"),
        description: text(form, "description") || undefined,
        distributions: regions.map((r) => ({
          region: r,
          amiDistributionConfiguration: {
            ...(amiName ? { name: amiName } : {}),
            ...(accounts.length ? { launchPermission: { userIds: accounts } } : {}),
          },
        })),
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, { revalidate: [path], fields: { name: "name", "amiDistributionConfiguration.name": "amiName", region: "regions", userIds: "accounts" } });
}

export async function createContainerRecipe(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const components = form.getAll("component").map(String);
    if (!components.length) throw new Error("Choose at least one component");
    await (await imagebuilder()).send(
      new CreateContainerRecipeCommand({
        containerType: "DOCKER",
        name: required(form, "name", "Name"),
        semanticVersion: text(form, "version") || "1.0.0",
        parentImage: required(form, "parent", "Base image"),
        components: components.map((componentArn) => ({ componentArn })),
        dockerfileTemplateData: text(form, "dockerfile") || "FROM {{{ imagebuilder:parentImage }}}\n{{{ imagebuilder:environments }}}\n{{{ imagebuilder:components }}}",
        targetRepository: { service: "ECR", repositoryName: required(form, "repository", "Repository") },
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, { revalidate: [path], fields: { name: "name", semanticVersion: "version", parentImage: "parent", repositoryName: "repository", dockerfileTemplateData: "dockerfile" } });
}

export async function createWorkflow(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await imagebuilder()).send(
      new CreateWorkflowCommand({
        name: required(form, "name", "Name"),
        semanticVersion: text(form, "version") || "1.0.0",
        type: (text(form, "type") || "BUILD") as WorkflowType,
        description: text(form, "description") || undefined,
        data: required(form, "data", "Document"),
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, { revalidate: [path], fields: { name: "name", semanticVersion: "version", data: "data" } });
}

const LIFECYCLE_ROLE = {
  name: "EC2ImageBuilderLifecycleExecutionRole",
  service: "imagebuilder.amazonaws.com",
  statements: [{ Effect: "Allow", Action: ["ec2:DescribeImages", "ec2:DeregisterImage", "ec2:DeleteSnapshot", "ec2:DisableImage", "ec2:EnableImageDeprecation", "ec2:CreateTags", "imagebuilder:GetImage", "imagebuilder:DeleteImage", "imagebuilder:ListImages", "imagebuilder:ListImageBuildVersions"], Resource: "*" }],
};

/** A lifecycle policy that deletes images older than a number of days, or
 * beyond a number of the newest, for images of the recipes named. */
export async function createLifecyclePolicy(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const recipes = form.getAll("recipe").map(String);
    if (!recipes.length) throw new Error("Choose at least one recipe");
    const count = Number(required(form, "count", "Keep"));
    const by = text(form, "by") === "AGE" ? "AGE" : "COUNT";
    await (await imagebuilder()).send(
      new CreateLifecyclePolicyCommand({
        name: required(form, "name", "Name"),
        description: text(form, "description") || undefined,
        executionRole: await roleFrom(form, "role", LIFECYCLE_ROLE),
        resourceType: "AMI_IMAGE",
        status: "ENABLED",
        policyDetails: [{ action: { type: (text(form, "action") || "DELETE") as "DELETE" | "DEPRECATE" | "DISABLE" }, filter: by === "AGE" ? { type: "AGE", value: count, unit: "DAYS" } : { type: "COUNT", value: count } }],
        resourceSelection: { recipes: recipes.map((r) => ({ name: r.split("|")[0], semanticVersion: r.split("|")[1] })) },
        clientToken: randomUUID(),
      }),
    );
    return "Created";
  }, { revalidate: [path], fields: { name: "name", executionRole: "role", value: "count" } });
}
