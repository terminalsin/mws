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
import { act, FieldError, mws, required, text, type ActionResult } from "@mws-dashboard/aws";
import { ROLES, bucketOptions, ensureLogGroup, roleFrom } from "@mws-dashboard/aws/auto";
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
  }, {
    fields: {
      modelId: "model",
      "inferenceConfig.temperature": "temperature",
      "inferenceConfig.maxTokens": "maxTokens",
      "system.text": "system",
      "messages.content.text": "prompt",
      "guardrailConfig.guardrailIdentifier": "guardrail",
    },
  });
}

const FILTERS: GuardrailContentFilterType[] = ["HATE", "INSULTS", "SEXUAL", "VIOLENCE", "MISCONDUCT", "PROMPT_ATTACK"];

/** A denied topic from a `Name: definition` line (a bare line is both). */
function topic(line: string) {
  const i = line.indexOf(":");
  const name = (i > 0 ? line.slice(0, i) : line).trim();
  return { name: name.slice(0, 100).replace(/[^\w\s!?.-]/g, "").trim() || "Topic", definition: (i > 0 ? line.slice(i + 1) : line).trim() || name, type: "DENY" as const };
}

export async function createGuardrail(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const strength = text(form, "strength") || "MEDIUM";
    const topics = text(form, "topics").split("\n").map((t) => t.trim()).filter(Boolean);
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
          ? { topicsConfig: topics.map((t) => topic(t)) }
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
  }, {
    fields: {
      name: "name",
      blockedInputMessaging: "blocked",
      blockedOutputsMessaging: "blocked",
      "topicPolicyConfig.topicsConfig.name": "topics",
      "topicPolicyConfig.topicsConfig.definition": "topics",
      "wordPolicyConfig.wordsConfig.text": "words",
    },
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
  }, { fields: { "content.text.text": "text", guardrailVersion: "version", source: "source" } });
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
  }, { revalidate: ["/bedrock/profiles"], fields: { inferenceProfileName: "name", "modelSource.copyFrom": "source", "tags.value": "costCenter" } });
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
    if (!group && !bucket) throw new FieldError("logGroup", "Choose a log group or a bucket", "required");
    // Deliveries to a bucket that does not exist would only fail later.
    if (bucket && !(await bucketOptions()).some((b) => b.value === bucket)) throw new FieldError("bucket", "No such bucket", "missing");
    const roleArn = group ? await roleFrom(form, "role", ROLES.bedrockLogging) : undefined;
    if (group) await ensureLogGroup(group);
    await (await bedrock()).send(
      new PutModelInvocationLoggingConfigurationCommand({
        loggingConfig: {
          cloudWatchConfig: group && roleArn ? { logGroupName: group, roleArn } : undefined,
          s3Config: bucket ? { bucketName: bucket, keyPrefix: text(form, "prefix") || undefined } : undefined,
          textDataDeliveryEnabled: true,
          imageDataDeliveryEnabled: text(form, "images") === "on",
          embeddingDataDeliveryEnabled: text(form, "embeddings") === "on",
          videoDataDeliveryEnabled: false,
        },
      }),
    );
    return "Saved";
  }, {
    revalidate: ["/bedrock/settings"],
    fields: {
      "loggingConfig.cloudWatchConfig.logGroupName": "logGroup",
      logGroupName: "logGroup",
      "loggingConfig.cloudWatchConfig.roleArn": "role",
      "loggingConfig.s3Config.bucketName": "bucket",
      "loggingConfig.s3Config.keyPrefix": "prefix",
    },
  });
}

export async function stopLogging() {
  return act(async () => {
    await (await bedrock()).send(new DeleteModelInvocationLoggingConfigurationCommand({}));
    return "Logging off";
  }, "/bedrock/settings");
}

/** `key=value` lines (or commas) in `form[field]` as an object. */
function pairs(form: FormData, field: string): Record<string, string> | undefined {
  const entries = list(text(form, field)).map((kv) => {
    const i = kv.indexOf("=");
    if (i < 1) throw new FieldError(field, `"${kv}" is not key=value`, "format");
    return [kv.slice(0, i).trim(), kv.slice(i + 1).trim()] as const;
  });
  return entries.length ? Object.fromEntries(entries) : undefined;
}

export async function saveProvider(existing: string | null, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = existing ?? required(form, "name", "Name").toLowerCase();
    const raw = text(form, "params");
    let params: unknown;
    if (raw) {
      try {
        params = JSON.parse(raw);
      } catch {
        throw new FieldError("params", "Not valid JSON", "format");
      }
      if (!params || typeof params !== "object" || Array.isArray(params)) throw new FieldError("params", "A JSON object, like {\"temperature\": 0.2}", "format");
    }
    const timeout = text(form, "timeout");
    const config = {
      kind: text(form, "kind") || undefined,
      url: text(form, "url") || undefined,
      apiKey: text(form, "clearKey") === "on" ? "" : text(form, "apiKey") || undefined,
      model: text(form, "model") || undefined,
      models: list(text(form, "models")).length ? list(text(form, "models")) : undefined,
      modelMap: pairs(form, "modelMap"),
      headers: pairs(form, "headers"),
      params,
      timeoutSeconds: timeout ? Number(timeout) : undefined,
    };
    try {
      await mws(`/_aws/bedrock/providers/${encodeURIComponent(name)}`, { method: "PUT", json: config });
    } catch (e) {
      throw providerError(e);
    }
    if (text(form, "makeDefault") === "on") await mws("/_aws/bedrock/providers", { method: "PUT", json: { default: name } });
    return existing ? "Saved" : `Added ${name}`;
  }, "/bedrock/settings");
}

/** MWS's provider checks, on the field each one concerns. */
function providerError(e: unknown): unknown {
  const message = e instanceof Error ? e.message.replace(/^\S+ answered \d+: /, "") : "";
  const field = [
    [/^Provider name/, "name"],
    [/^Provider URL/, "url"],
    [/^timeoutSeconds/, "timeout"],
    [/^Header/, "headers"],
  ].find(([re]) => (re as RegExp).test(message))?.[1] as string | undefined;
  return field ? new FieldError(field, message) : e;
}

export async function forgetProvider(name: string) {
  return act(async () => {
    await mws(`/_aws/bedrock/providers/${encodeURIComponent(name)}`, { method: "DELETE" });
    return "Stored settings removed";
  }, "/bedrock/settings");
}

export async function setDefaultProvider(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await mws("/_aws/bedrock/providers", { method: "PUT", json: { default: required(form, "provider", "Provider") } });
    return "Default provider set";
  }, "/bedrock/settings");
}
