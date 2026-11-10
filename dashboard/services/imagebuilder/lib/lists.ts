import "server-only";

import {
  ListComponentsCommand,
  ListContainerRecipesCommand,
  ListDistributionConfigurationsCommand,
  ListImageBuildVersionsCommand,
  ListImagePipelinesCommand,
  ListImageRecipesCommand,
  ListImagesCommand,
  ListInfrastructureConfigurationsCommand,
  ListLifecyclePoliciesCommand,
  ListWorkflowsCommand,
  type Ownership,
} from "@aws-sdk/client-imagebuilder";
import { all } from "@mws-dashboard/aws";

import { imagebuilder } from "./clients";

// Image Builder pages at 25: every list here follows nextToken to the end.

export async function pipelines() {
  const c = await imagebuilder();
  return all(
    (nextToken) => c.send(new ListImagePipelinesCommand({ nextToken })),
    (r) => r.imagePipelineList,
    (r) => r.nextToken,
  );
}

export async function recipes(owner: Ownership = "Self") {
  const c = await imagebuilder();
  return all(
    (nextToken) => c.send(new ListImageRecipesCommand({ owner, nextToken })),
    (r) => r.imageRecipeSummaryList,
    (r) => r.nextToken,
  );
}

export async function containerRecipes() {
  const c = await imagebuilder();
  return all(
    (nextToken) => c.send(new ListContainerRecipesCommand({ owner: "Self", nextToken })),
    (r) => r.containerRecipeSummaryList,
    (r) => r.nextToken,
  );
}

export async function infrastructures() {
  const c = await imagebuilder();
  return all(
    (nextToken) => c.send(new ListInfrastructureConfigurationsCommand({ nextToken })),
    (r) => r.infrastructureConfigurationSummaryList,
    (r) => r.nextToken,
  );
}

export async function distributions() {
  const c = await imagebuilder();
  return all(
    (nextToken) => c.send(new ListDistributionConfigurationsCommand({ nextToken })),
    (r) => r.distributionConfigurationSummaryList,
    (r) => r.nextToken,
  );
}

export async function components(owner: Ownership = "Self") {
  const c = await imagebuilder();
  return all(
    (nextToken) => c.send(new ListComponentsCommand({ owner, nextToken })),
    (r) => r.componentVersionList,
    (r) => r.nextToken,
  );
}

export async function images(owner: Ownership = "Self") {
  const c = await imagebuilder();
  return all(
    (nextToken) => c.send(new ListImagesCommand({ owner, nextToken })),
    (r) => r.imageVersionList,
    (r) => r.nextToken,
  );
}

/** Every build of every image version, newest first. */
export async function builds() {
  const c = await imagebuilder();
  const versions = await images("Self");
  const each = await Promise.all(
    versions.map((v) =>
      all(
        (nextToken) => c.send(new ListImageBuildVersionsCommand({ imageVersionArn: v.arn, nextToken })),
        (r) => r.imageSummaryList,
        (r) => r.nextToken,
      ),
    ),
  );
  return each.flat().sort((a, b) => (b.dateCreated ?? "").localeCompare(a.dateCreated ?? ""));
}

export async function workflows() {
  const c = await imagebuilder();
  return all(
    (nextToken) => c.send(new ListWorkflowsCommand({ owner: "Self", nextToken })),
    (r) => r.workflowVersionList,
    (r) => r.nextToken,
  );
}

export async function lifecyclePolicies() {
  const c = await imagebuilder();
  return all(
    (nextToken) => c.send(new ListLifecyclePoliciesCommand({ nextToken })),
    (r) => r.lifecyclePolicySummaryList,
    (r) => r.nextToken,
  );
}

/** "arn:…:image/name/1.2.3/4" → "1.2.3/4". */
export const versionOf = (arn: string | undefined) => arn?.split("/").slice(2).join("/");
