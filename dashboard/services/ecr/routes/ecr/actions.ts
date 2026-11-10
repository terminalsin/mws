"use server";

import {
  BatchDeleteImageCommand,
  CreatePullThroughCacheRuleCommand,
  CreateRepositoryCommand,
  CreateRepositoryCreationTemplateCommand,
  DeleteLifecyclePolicyCommand,
  DeletePullThroughCacheRuleCommand,
  DeleteRegistryPolicyCommand,
  DeleteRepositoryCommand,
  DeleteRepositoryCreationTemplateCommand,
  DeleteRepositoryPolicyCommand,
  PutAccountSettingCommand,
  PutImageScanningConfigurationCommand,
  PutImageTagMutabilityCommand,
  PutLifecyclePolicyCommand,
  PutRegistryPolicyCommand,
  PutRegistryScanningConfigurationCommand,
  PutReplicationConfigurationCommand,
  SetRepositoryPolicyCommand,
  StartImageScanCommand,
  StartLifecyclePolicyPreviewCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateImageStorageClassCommand,
  type EncryptionType,
  type ImageTagMutability,
  type RCTAppliedFor,
  type ReplicationDestination,
  type UpstreamRegistry,
} from "@aws-sdk/client-ecr";
import { CreateRepositoryCommand as CreatePublicRepositoryCommand, DeleteRepositoryCommand as DeletePublicRepositoryCommand, PutRepositoryCatalogDataCommand, SetRepositoryPolicyCommand as SetPublicRepositoryPolicyCommand, DeleteRepositoryPolicyCommand as DeletePublicRepositoryPolicyCommand } from "@aws-sdk/client-ecr-public";
import { act, checkFailures, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ecr, ecrPublic, publicHref, repoHref } from "../../lib/clients";

const PAGES = ["/ecr", "/ecr/repo", "/ecr/image"];

const tagLines = (value: string) =>
  value
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [Key, ...rest] = l.split("=");
      return { Key: Key.trim(), Value: rest.join("=").trim() };
    });

const filters = (value: string) =>
  value
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((filter) => ({ filterType: "WILDCARD" as const, filter }));

function jsonText(form: FormData, field: string) {
  const v = text(form, field);
  if (!v) return "";
  try {
    JSON.parse(v);
  } catch {
    throw new FieldError(field, "Invalid JSON", "format");
  }
  return v;
}

const keepLast = (keep: number) => JSON.stringify({ rules: [{ rulePriority: 1, description: `Keep the last ${keep} images`, selection: { tagStatus: "any", countType: "imageCountMoreThan", countNumber: keep }, action: { type: "expire" } }] });

export async function createRepository(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Repository name");
    const client = await ecr();
    const kms = text(form, "encryption") === "KMS";
    await client.send(
      new CreateRepositoryCommand({
        repositoryName: name,
        imageTagMutability: text(form, "immutable") === "on" ? "IMMUTABLE" : "MUTABLE",
        imageScanningConfiguration: { scanOnPush: text(form, "scan") === "on" },
        encryptionConfiguration: kms ? { encryptionType: "KMS", kmsKey: text(form, "kms") || undefined } : undefined,
      }),
    );
    const keep = Number(text(form, "keep") || 0);
    if (keep > 0) await client.send(new PutLifecyclePolicyCommand({ repositoryName: name, lifecyclePolicyText: keepLast(keep) }));
    redirect(repoHref(name));
  }, { revalidate: ["/ecr"], fields: { repositoryName: "name", LifecyclePolicyValidationException: "keep", kmsKey: "kms", KmsException: "kms" } });
}

export async function deleteRepository(name: string) {
  return act(async () => {
    await (await ecr()).send(new DeleteRepositoryCommand({ repositoryName: name, force: true }));
    redirect("/ecr");
  });
}

/** BatchDeleteImage answers 200 with per-image `failures` (an image a
 * manifest list still references, one already gone): report them. */
export async function deleteImage(repo: string, digest: string, back: string | null) {
  return act(async () => {
    const out = await (await ecr()).send(new BatchDeleteImageCommand({ repositoryName: repo, imageIds: [{ imageDigest: digest }] }));
    checkFailures(out.failures, (f) => `${f.imageId?.imageTag ?? f.imageId?.imageDigest?.slice(0, 19)}: ${f.failureCode} ${f.failureReason ?? ""}`.trim());
    if (back) redirect(back);
    return "Image deleted";
  }, ...PAGES);
}

export async function startScan(repo: string, digest: string) {
  return act(async () => {
    await (await ecr()).send(new StartImageScanCommand({ repositoryName: repo, imageId: { imageDigest: digest } }));
    return "Scan started";
  }, ...PAGES);
}

export async function setStorageClass(repo: string, digest: string, archive: boolean) {
  return act(async () => {
    await (await ecr()).send(new UpdateImageStorageClassCommand({ repositoryName: repo, imageId: { imageDigest: digest }, targetStorageClass: archive ? "ARCHIVE" : "STANDARD" }));
    return archive ? "Image archived" : "Restoring image";
  }, ...PAGES);
}

export async function saveSettings(repo: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ecr();
    const mutability = (text(form, "mutability") || "MUTABLE") as ImageTagMutability;
    const exclusions = filters(text(form, "exclusions"));
    if (/_WITH_EXCLUSION$/.test(mutability) && !exclusions.length) throw new FieldError("exclusions", "Add at least one tag filter", "required");
    await client.send(
      new PutImageTagMutabilityCommand({ repositoryName: repo, imageTagMutability: mutability, imageTagMutabilityExclusionFilters: /_WITH_EXCLUSION$/.test(mutability) ? exclusions : undefined }),
    );
    await client.send(new PutImageScanningConfigurationCommand({ repositoryName: repo, imageScanningConfiguration: { scanOnPush: text(form, "scan") === "on" } }));
    return "Settings saved";
  }, { revalidate: PAGES, fields: { imageTagMutability: "mutability", imageTagMutabilityExclusionFilters: "exclusions" } });
}

export async function saveRepositoryPolicy(repo: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = jsonText(form, "policy");
    const client = await ecr();
    if (!policy) {
      await client.send(new DeleteRepositoryPolicyCommand({ repositoryName: repo }));
      return "Policy removed";
    }
    await client.send(new SetRepositoryPolicyCommand({ repositoryName: repo, policyText: policy }));
    return "Policy saved";
  }, { revalidate: PAGES, fields: { policyText: "policy", InvalidParameterException: "policy" } });
}

export async function saveLifecyclePolicy(repo: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = jsonText(form, "policy");
    const client = await ecr();
    if (!policy) {
      await client.send(new DeleteLifecyclePolicyCommand({ repositoryName: repo }));
      return "Lifecycle policy removed";
    }
    await client.send(new PutLifecyclePolicyCommand({ repositoryName: repo, lifecyclePolicyText: policy }));
    return "Lifecycle policy saved";
  }, { revalidate: PAGES, fields: { lifecyclePolicyText: "policy", LifecyclePolicyValidationException: "policy", InvalidParameterException: "policy" } });
}

export async function previewLifecycle(repo: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = jsonText(form, "policy");
    await (await ecr()).send(new StartLifecyclePolicyPreviewCommand({ repositoryName: repo, lifecyclePolicyText: policy || undefined }));
    return "Preview started";
  }, { revalidate: PAGES, fields: { lifecyclePolicyText: "policy", LifecyclePolicyValidationException: "policy", LifecyclePolicyPreviewInProgressException: "policy" } });
}

export async function saveTags(arn: string, current: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const tags = tagLines(text(form, "tags"));
    const client = await ecr();
    const gone = current.filter((k) => !tags.some((t) => t.Key === k));
    if (gone.length) await client.send(new UntagResourceCommand({ resourceArn: arn, tagKeys: gone }));
    if (tags.length) await client.send(new TagResourceCommand({ resourceArn: arn, tags }));
    return "Tags saved";
  }, { revalidate: PAGES, fields: { tags: "tags", InvalidTagParameterException: "tags", TooManyTagsException: "tags" } });
}

// --- Private registry ------------------------------------------------------------

export async function saveReplication(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const destinations: ReplicationDestination[] = text(form, "destinations")
      .split(/[\n,]+/)
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [region, registryId] = l.split(/[\s:@]+/);
        return { region, registryId: registryId || text(form, "account") };
      });
    const prefixes = text(form, "prefixes").split(/[\s,]+/).filter(Boolean);
    await (await ecr()).send(
      new PutReplicationConfigurationCommand({
        replicationConfiguration: {
          rules: destinations.length ? [{ destinations, repositoryFilters: prefixes.length ? prefixes.map((filter) => ({ filter, filterType: "PREFIX_MATCH" })) : undefined }] : [],
        },
      }),
    );
    return destinations.length ? "Replication saved" : "Replication off";
  }, { revalidate: ["/ecr"], fields: { "replicationConfiguration.rules.destinations": "destinations", region: "destinations", registryId: "destinations", "replicationConfiguration.rules.repositoryFilters": "prefixes" } });
}

export async function createPullThrough(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ecr()).send(
      new CreatePullThroughCacheRuleCommand({
        ecrRepositoryPrefix: required(form, "prefix", "Repository prefix"),
        upstreamRegistryUrl: required(form, "url", "Upstream registry URL"),
        upstreamRegistry: (text(form, "upstream") || undefined) as UpstreamRegistry | undefined,
        credentialArn: text(form, "credential") || undefined,
      }),
    );
    return "Pull through cache rule created";
  }, { revalidate: ["/ecr"], fields: { ecrRepositoryPrefix: "prefix", upstreamRegistryUrl: "url", upstreamRegistry: "upstream", credentialArn: "credential", PullThroughCacheRuleAlreadyExistsException: "prefix", UnsupportedUpstreamRegistryException: "url", SecretNotFoundException: "credential" } });
}

export async function deletePullThrough(prefix: string) {
  return act(async () => {
    await (await ecr()).send(new DeletePullThroughCacheRuleCommand({ ecrRepositoryPrefix: prefix }));
    return "Rule deleted";
  }, "/ecr");
}

export async function createTemplate(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const appliedFor = form.getAll("appliedFor").map(String) as RCTAppliedFor[];
    if (!appliedFor.length) throw new FieldError("appliedFor", "Choose when it applies", "required");
    const encryption = text(form, "encryption") as EncryptionType;
    await (await ecr()).send(
      new CreateRepositoryCreationTemplateCommand({
        prefix: required(form, "prefix", "Prefix"),
        description: text(form, "description") || undefined,
        appliedFor,
        imageTagMutability: text(form, "immutable") === "on" ? "IMMUTABLE" : "MUTABLE",
        encryptionConfiguration: encryption ? { encryptionType: encryption, kmsKey: text(form, "kms") || undefined } : undefined,
        lifecyclePolicy: Number(text(form, "keep")) > 0 ? keepLast(Number(text(form, "keep"))) : undefined,
      }),
    );
    return "Template created";
  }, { revalidate: ["/ecr"], fields: { prefix: "prefix", TemplateAlreadyExistsException: "prefix", description: "description", "encryptionConfiguration.kmsKey": "kms" } });
}

export async function deleteTemplate(prefix: string) {
  return act(async () => {
    await (await ecr()).send(new DeleteRepositoryCreationTemplateCommand({ prefix }));
    return "Template deleted";
  }, "/ecr");
}

export async function saveRegistryPolicy(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = jsonText(form, "policy");
    const client = await ecr();
    if (!policy) {
      await client.send(new DeleteRegistryPolicyCommand({}));
      return "Registry policy removed";
    }
    await client.send(new PutRegistryPolicyCommand({ policyText: policy }));
    return "Registry policy saved";
  }, { revalidate: ["/ecr"], fields: { policyText: "policy", InvalidParameterException: "policy" } });
}

export async function saveScanning(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const frequency = text(form, "frequency");
    const filtersList = text(form, "filters").split(/[\s,]+/).filter(Boolean);
    await (await ecr()).send(
      new PutRegistryScanningConfigurationCommand({
        scanType: (text(form, "scanType") || "BASIC") as "BASIC" | "ENHANCED",
        rules: frequency ? [{ scanFrequency: frequency as "SCAN_ON_PUSH" | "CONTINUOUS_SCAN" | "MANUAL", repositoryFilters: (filtersList.length ? filtersList : ["*"]).map((filter) => ({ filter, filterType: "WILDCARD" })) }] : [],
      }),
    );
    return "Scanning configuration saved";
  }, { revalidate: ["/ecr"], fields: { scanType: "scanType", rules: "filters" } });
}

export async function setAccountSetting(name: string, value: string) {
  return act(async () => {
    await (await ecr()).send(new PutAccountSettingCommand({ name, value }));
    return `${name}: ${value}`;
  }, "/ecr");
}

// --- ECR Public ----------------------------------------------------------------------

export async function createPublicRepository(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Repository name");
    const split = (v: string) => v.split(/\s*[,\n]\s*/).map((s) => s.trim()).filter(Boolean);
    await (await ecrPublic()).send(
      new CreatePublicRepositoryCommand({
        repositoryName: name,
        catalogData: {
          description: text(form, "description") || undefined,
          aboutText: text(form, "about") || undefined,
          usageText: text(form, "usage") || undefined,
          architectures: split(text(form, "architectures")),
          operatingSystems: split(text(form, "os")),
        },
      }),
    );
    redirect(publicHref(name));
  }, { revalidate: ["/ecr"], fields: { repositoryName: "name", RepositoryAlreadyExistsException: "name", "catalogData.description": "description", "catalogData.architectures": "architectures", "catalogData.operatingSystems": "os" } });
}

export async function deletePublicRepository(name: string) {
  return act(async () => {
    await (await ecrPublic()).send(new DeletePublicRepositoryCommand({ repositoryName: name, force: true }));
    redirect("/ecr?tab=public");
  });
}

export async function savePublicCatalog(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const split = (v: string) => v.split(/\s*[,\n]\s*/).map((s) => s.trim()).filter(Boolean);
    await (await ecrPublic()).send(
      new PutRepositoryCatalogDataCommand({
        repositoryName: name,
        catalogData: { description: text(form, "description"), aboutText: text(form, "about"), usageText: text(form, "usage"), architectures: split(text(form, "architectures")), operatingSystems: split(text(form, "os")) },
      }),
    );
    return "Catalog data saved";
  }, { revalidate: ["/ecr/public"], fields: { "catalogData.description": "description", "catalogData.architectures": "architectures", "catalogData.operatingSystems": "os" } });
}

export async function savePublicPolicy(name: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const policy = jsonText(form, "policy");
    const client = await ecrPublic();
    if (!policy) {
      await client.send(new DeletePublicRepositoryPolicyCommand({ repositoryName: name }));
      return "Policy removed";
    }
    await client.send(new SetPublicRepositoryPolicyCommand({ repositoryName: name, policyText: policy }));
    return "Policy saved";
  }, { revalidate: ["/ecr/public"], fields: { policyText: "policy", InvalidParameterException: "policy" } });
}
