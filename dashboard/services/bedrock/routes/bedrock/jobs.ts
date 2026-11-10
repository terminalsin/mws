"use server";

// Custom models and their training jobs, Provisioned Throughput, batch
// inference jobs, asynchronous invocations and resource tags.

import {
  CreateModelCustomizationJobCommand,
  CreateModelInvocationJobCommand,
  CreateProvisionedModelThroughputCommand,
  DeleteCustomModelCommand,
  DeleteProvisionedModelThroughputCommand,
  ListTagsForResourceCommand,
  StopModelCustomizationJobCommand,
  StopModelInvocationJobCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateProvisionedModelThroughputCommand,
  type CommitmentDuration,
  type CustomizationType,
} from "@aws-sdk/client-bedrock";
import { StartAsyncInvokeCommand } from "@aws-sdk/client-bedrock-runtime";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { roleFrom, type RoleSpec } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { bedrock, bedrockRuntime } from "../../lib/clients";

const s3Access = { Effect: "Allow", Action: ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"], Resource: "*" };

const CUSTOMIZATION_ROLE: RoleSpec = { name: "AmazonBedrockCustomizationRole", service: "bedrock.amazonaws.com", statements: [s3Access] };
const BATCH_ROLE: RoleSpec = {
  name: "AmazonBedrockBatchInferenceRole",
  service: "bedrock.amazonaws.com",
  statements: [s3Access, { Effect: "Allow", Action: ["bedrock:InvokeModel"], Resource: "*" }],
};

/** `key=value` lines as Bedrock tags (`{ key, value }`). */
function tagLines(form: FormData, field: string) {
  return text(form, field)
    .split(/\n+/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf("=");
      if (i < 1) throw new FieldError(field, `"${l}" is not key=value`, "format");
      return { key: l.slice(0, i).trim(), value: l.slice(i + 1).trim() };
    });
}

function pairs(form: FormData, field: string): Record<string, string> | undefined {
  const tags = tagLines(form, field);
  return tags.length ? Object.fromEntries(tags.map((t) => [t.key, t.value])) : undefined;
}

const q = (arn: string) => encodeURIComponent(arn);

// Custom models ----------------------------------------------------------------

export async function createCustomizationJob(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const roleArn = await roleFrom(form, "role", CUSTOMIZATION_ROLE);
      const validation = text(form, "validation");
      const tags = tagLines(form, "tags");
      const out = await (await bedrock()).send(
        new CreateModelCustomizationJobCommand({
          jobName: required(form, "jobName", "Job name"),
          customModelName: required(form, "modelName", "Model name"),
          baseModelIdentifier: required(form, "base", "Base model"),
          customizationType: (text(form, "type") || "FINE_TUNING") as CustomizationType,
          roleArn,
          trainingDataConfig: { s3Uri: required(form, "training", "Training data") },
          validationDataConfig: validation ? { validators: [{ s3Uri: validation }] } : undefined,
          outputDataConfig: { s3Uri: required(form, "output", "Output location") },
          hyperParameters: pairs(form, "hyper"),
          customModelKmsKeyId: text(form, "kms") || undefined,
          customModelTags: tags.length ? tags : undefined,
        }),
      );
      redirect(`/bedrock/customization-job?arn=${q(out.jobArn!)}`);
    },
    {
      fields: {
        jobName: "jobName",
        customModelName: "modelName",
        baseModelIdentifier: "base",
        roleArn: "role",
        "trainingDataConfig.s3Uri": "training",
        "validationDataConfig.validators.s3Uri": "validation",
        "outputDataConfig.s3Uri": "output",
        customModelKmsKeyId: "kms",
        hyperParameters: "hyper",
        customModelTags: "tags",
      },
    },
  );
}

export async function stopCustomizationJob(arn: string) {
  return act(async () => {
    await (await bedrock()).send(new StopModelCustomizationJobCommand({ jobIdentifier: arn }));
    return "Stopping";
  }, "/bedrock/customization-job");
}

export async function deleteCustomModel(arn: string) {
  return act(async () => {
    await (await bedrock()).send(new DeleteCustomModelCommand({ modelIdentifier: arn }));
    redirect("/bedrock/custom-models");
  });
}

// Provisioned Throughput ----------------------------------------------------------

export async function createProvisioned(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const commitment = text(form, "commitment");
      const tags = tagLines(form, "tags");
      const out = await (await bedrock()).send(
        new CreateProvisionedModelThroughputCommand({
          provisionedModelName: required(form, "name", "Name"),
          modelId: required(form, "model", "Model"),
          modelUnits: Number(required(form, "units", "Model units")),
          commitmentDuration: commitment ? (commitment as CommitmentDuration) : undefined,
          tags: tags.length ? tags : undefined,
        }),
      );
      redirect(`/bedrock/provisioned-model?arn=${q(out.provisionedModelArn!)}`);
    },
    { fields: { provisionedModelName: "name", modelId: "model", modelUnits: "units", tags: "tags", ResourceNotFoundException: "model" } },
  );
}

export async function updateProvisioned(arn: string, current: { name: string; model: string }, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const name = required(form, "name", "Name");
      const model = text(form, "model");
      if (name === current.name && (!model || model === current.model)) return "Nothing to change";
      await (await bedrock()).send(
        new UpdateProvisionedModelThroughputCommand({
          provisionedModelId: arn,
          desiredProvisionedModelName: name !== current.name ? name : undefined,
          desiredModelId: model && model !== current.model ? model : undefined,
        }),
      );
      return "Updating";
    },
    { revalidate: ["/bedrock/provisioned-model", "/bedrock/provisioned"], fields: { desiredProvisionedModelName: "name", desiredModelId: "model" } },
  );
}

export async function deleteProvisioned(arn: string) {
  return act(async () => {
    await (await bedrock()).send(new DeleteProvisionedModelThroughputCommand({ provisionedModelId: arn }));
    redirect("/bedrock/provisioned");
  });
}

// Batch inference ------------------------------------------------------------------

export async function createBatchJob(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const roleArn = await roleFrom(form, "role", BATCH_ROLE);
      const timeout = text(form, "timeout");
      const tags = tagLines(form, "tags");
      const out = await (await bedrock()).send(
        new CreateModelInvocationJobCommand({
          jobName: required(form, "jobName", "Job name"),
          modelId: required(form, "model", "Model"),
          roleArn,
          inputDataConfig: { s3InputDataConfig: { s3Uri: required(form, "input", "Input data"), s3InputFormat: "JSONL" } },
          outputDataConfig: { s3OutputDataConfig: { s3Uri: required(form, "output", "Output location") } },
          timeoutDurationInHours: timeout ? Number(timeout) : undefined,
          tags: tags.length ? tags : undefined,
        }),
      );
      redirect(`/bedrock/batch-job?arn=${q(out.jobArn!)}`);
    },
    {
      fields: {
        jobName: "jobName",
        modelId: "model",
        roleArn: "role",
        "inputDataConfig.s3InputDataConfig.s3Uri": "input",
        "outputDataConfig.s3OutputDataConfig.s3Uri": "output",
        timeoutDurationInHours: "timeout",
        tags: "tags",
      },
    },
  );
}

export async function stopBatchJob(arn: string) {
  return act(async () => {
    await (await bedrock()).send(new StopModelInvocationJobCommand({ jobIdentifier: arn }));
    return "Stopping";
  }, "/bedrock/batch-job");
}

// Asynchronous invocations -----------------------------------------------------------

export async function startAsyncInvoke(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const raw = required(form, "input", "Model input");
      let modelInput: unknown;
      try {
        modelInput = JSON.parse(raw);
      } catch {
        throw new FieldError("input", "Not valid JSON", "format");
      }
      const tags = tagLines(form, "tags");
      const out = await (await bedrockRuntime()).send(
        new StartAsyncInvokeCommand({
          modelId: required(form, "model", "Model"),
          modelInput: modelInput as never,
          outputDataConfig: { s3OutputDataConfig: { s3Uri: required(form, "output", "Output location") } },
          tags: tags.length ? tags : undefined,
        }),
      );
      redirect(`/bedrock/async-invoke?arn=${q(out.invocationArn!)}`);
    },
    { fields: { modelId: "model", modelInput: "input", "outputDataConfig.s3OutputDataConfig.s3Uri": "output", tags: "tags", ValidationException: "input" } },
  );
}

// Tags ---------------------------------------------------------------------------------

/** Replace a resource's tags with the `key=value` lines in `form.tags`. */
export async function saveTags(arn: string, path: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const wanted = tagLines(form, "tags");
      const c = await bedrock();
      const current = (await c.send(new ListTagsForResourceCommand({ resourceARN: arn }))).tags ?? [];
      const gone = current.filter((t) => !wanted.some((w) => w.key === t.key)).map((t) => t.key!);
      const changed = wanted.filter((w) => !current.some((t) => t.key === w.key && t.value === w.value));
      if (gone.length) await c.send(new UntagResourceCommand({ resourceARN: arn, tagKeys: gone }));
      if (changed.length) await c.send(new TagResourceCommand({ resourceARN: arn, tags: changed }));
      return gone.length || changed.length ? "Tags saved" : "Nothing to change";
    },
    { revalidate: [path], fields: { tags: "tags", "tags.key": "tags", "tags.value": "tags", tagKeys: "tags" } },
  );
}
