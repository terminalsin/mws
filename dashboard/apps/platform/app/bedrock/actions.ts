"use server";

import {
  CreateGuardrailCommand,
  CreateGuardrailVersionCommand,
  CreateInferenceProfileCommand,
  DeleteGuardrailCommand,
  DeleteInferenceProfileCommand,
  DeleteModelInvocationLoggingConfigurationCommand,
  PutModelInvocationLoggingConfigurationCommand,
  type GuardrailContentFilterType,
  type GuardrailPiiEntityType,
} from "@aws-sdk/client-bedrock";
import { ApplyGuardrailCommand, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { bedrock, bedrockRuntime } from "../../lib/clients";

const list = (s: string) => s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);

export async function converse(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const modelId = required(form, "model", "Model");
    const system = text(form, "system");
    const guardrail = text(form, "guardrail");
    const out = await (await bedrockRuntime()).send(
      new ConverseCommand({
        modelId,
        system: system ? [{ text: system }] : undefined,
        messages: [{ role: "user", content: [{ text: required(form, "prompt", "Prompt") }] }],
        inferenceConfig: { maxTokens: Number(text(form, "maxTokens")) || 512, temperature: Number(text(form, "temperature") || "0.7") },
        guardrailConfig: guardrail ? { guardrailIdentifier: guardrail, guardrailVersion: "DRAFT" } : undefined,
      }),
    );
    const reply = (out.output?.message?.content ?? []).map((c) => c.text ?? (c.toolUse ? JSON.stringify(c.toolUse, null, 2) : "")).join("\n");
    const blocked = out.stopReason === "guardrail_intervened";
    return {
      ok: !blocked,
      message: `${out.usage?.inputTokens ?? 0} → ${out.usage?.outputTokens ?? 0} tokens · ${out.metrics?.latencyMs ?? 0} ms${blocked ? " · blocked by guardrail" : ""}`,
      detail: reply || "(empty)",
    };
  });
}

const FILTERS: GuardrailContentFilterType[] = ["HATE", "INSULTS", "SEXUAL", "VIOLENCE", "MISCONDUCT", "PROMPT_ATTACK"];

export async function createGuardrail(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const strength = text(form, "strength") || "MEDIUM";
    const topics = list(text(form, "topics"));
    const words = list(text(form, "words"));
    const pii = form.getAll("pii").map(String) as GuardrailPiiEntityType[];
    const out = await (await bedrock()).send(
      new CreateGuardrailCommand({
        name: required(form, "name", "Name"),
        blockedInputMessaging: text(form, "blocked") || "Sorry, I can't help with that.",
        blockedOutputsMessaging: text(form, "blocked") || "Sorry, I can't help with that.",
        contentPolicyConfig:
          strength === "NONE"
            ? undefined
            : {
                filtersConfig: FILTERS.map((type) => ({
                  type,
                  inputStrength: strength as "LOW" | "MEDIUM" | "HIGH",
                  outputStrength: type === "PROMPT_ATTACK" ? "NONE" : (strength as "LOW" | "MEDIUM" | "HIGH"),
                })),
              },
        topicPolicyConfig: topics.length
          ? { topicsConfig: topics.map((t) => ({ name: t.slice(0, 100).replace(/[^\w\s!?.-]/g, ""), definition: t, type: "DENY" as const })) }
          : undefined,
        wordPolicyConfig:
          words.length || text(form, "profanity") === "on"
            ? {
                wordsConfig: words.length ? words.map((w) => ({ text: w })) : undefined,
                managedWordListsConfig: text(form, "profanity") === "on" ? [{ type: "PROFANITY" }] : undefined,
              }
            : undefined,
        sensitiveInformationPolicyConfig: pii.length ? { piiEntitiesConfig: pii.map((type) => ({ type, action: "ANONYMIZE" as const })) } : undefined,
      }),
    );
    redirect(`/bedrock/guardrail?id=${out.guardrailId}`);
  });
}

export async function testGuardrail(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await bedrockRuntime()).send(
      new ApplyGuardrailCommand({
        guardrailIdentifier: id,
        guardrailVersion: text(form, "version") || "DRAFT",
        source: text(form, "source") === "OUTPUT" ? "OUTPUT" : "INPUT",
        content: [{ text: { text: required(form, "text", "Text") } }],
      }),
    );
    const intervened = out.action === "GUARDRAIL_INTERVENED";
    const reasons = (out.assessments ?? []).flatMap((a) => [
      ...(a.topicPolicy?.topics ?? []).map((t) => `topic: ${t.name}`),
      ...(a.contentPolicy?.filters ?? []).map((f) => `content: ${f.type?.toLowerCase()} (${f.confidence?.toLowerCase()})`),
      ...(a.wordPolicy?.customWords ?? []).map((w) => `word: ${w.match}`),
      ...(a.wordPolicy?.managedWordLists ?? []).map((w) => `profanity: ${w.match}`),
      ...(a.sensitiveInformationPolicy?.piiEntities ?? []).map((p) => `${p.type?.toLowerCase()}: ${p.match}`),
    ]);
    return {
      ok: !intervened,
      message: intervened ? "Intervened" : "Passed",
      detail: intervened ? [...(out.outputs ?? []).map((o) => o.text), "", ...reasons].join("\n") : undefined,
    };
  });
}

export async function publishGuardrail(id: string) {
  return act(async () => {
    const out = await (await bedrock()).send(new CreateGuardrailVersionCommand({ guardrailIdentifier: id }));
    return `Version ${out.version}`;
  }, "/bedrock/guardrail");
}

export async function deleteGuardrail(id: string) {
  return act(async () => {
    await (await bedrock()).send(new DeleteGuardrailCommand({ guardrailIdentifier: id }));
    redirect("/bedrock/guardrails");
  });
}

export async function createProfile(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await bedrock()).send(
      new CreateInferenceProfileCommand({
        inferenceProfileName: required(form, "name", "Name"),
        modelSource: { copyFrom: required(form, "source", "Model") },
        tags: text(form, "costCenter") ? [{ key: "CostCenter", value: text(form, "costCenter") }] : undefined,
      }),
    );
    return "Created";
  }, "/bedrock/profiles");
}

export async function deleteProfile(arn: string) {
  return act(async () => {
    await (await bedrock()).send(new DeleteInferenceProfileCommand({ inferenceProfileIdentifier: arn }));
    return "Deleted";
  }, "/bedrock/profiles");
}

export async function saveLogging(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const group = text(form, "logGroup");
    const bucket = text(form, "bucket");
    if (!group && !bucket) throw new Error("Choose a log group or a bucket");
    await (await bedrock()).send(
      new PutModelInvocationLoggingConfigurationCommand({
        loggingConfig: {
          cloudWatchConfig: group ? { logGroupName: group, roleArn: required(form, "role", "Role") } : undefined,
          s3Config: bucket ? { bucketName: bucket, keyPrefix: text(form, "prefix") || undefined } : undefined,
          textDataDeliveryEnabled: true,
          imageDataDeliveryEnabled: text(form, "images") === "on",
          embeddingDataDeliveryEnabled: text(form, "embeddings") === "on",
          videoDataDeliveryEnabled: false,
        },
      }),
    );
    return "Saved";
  }, "/bedrock/settings");
}

export async function stopLogging() {
  return act(async () => {
    await (await bedrock()).send(new DeleteModelInvocationLoggingConfigurationCommand({}));
    return "Logging off";
  }, "/bedrock/settings");
}
