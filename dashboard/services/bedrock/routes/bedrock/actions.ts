"use server";

import {
  CreateGuardrailCommand,
  CreateGuardrailVersionCommand,
  CreateInferenceProfileCommand,
  DeleteGuardrailCommand,
  DeleteInferenceProfileCommand,
  DeleteModelInvocationLoggingConfigurationCommand,
  GetModelInvocationLoggingConfigurationCommand,
  PutModelInvocationLoggingConfigurationCommand,
  UpdateGuardrailCommand,
  type GuardrailContentFilterType,
  type GuardrailContextualGroundingFilterType,
  type GuardrailPiiEntityType,
  type GuardrailSensitiveInformationAction,
} from "@aws-sdk/client-bedrock";
import { ApplyGuardrailCommand, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
import { act, FieldError, mws, required, text, type ActionResult } from "@mws-dashboard/aws";
import { ROLES, bucketOptions, ensureLogGroup, roleFrom } from "@mws-dashboard/aws/auto";
import { redirect } from "next/navigation";

import { bedrock, bedrockRuntime } from "../../lib/clients";
import { FILTERS } from "../../lib/guardrail-presets";

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
    // Who answered, when it was a real provider rather than the echo.
    const via = await mws<{ provider: string; kind: string }>(`/_aws/bedrock/providers/route?modelId=${encodeURIComponent(modelId.split("/").pop()!.replace(/^(us|eu|apac|global)\./, ""))}`).catch(() => null);
    return {
      ok: !blocked,
      message: `${out.usage?.inputTokens ?? 0} → ${out.usage?.outputTokens ?? 0} tokens · ${out.metrics?.latencyMs ?? 0} ms${via && via.kind !== "echo" ? ` · ${via.provider}` : ""}${blocked ? " · blocked by guardrail" : ""}`,
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

/** A denied topic from a `Name: definition` line (a bare line is both). */
function topic(line: string) {
  const i = line.indexOf(":");
  const name = (i > 0 ? line.slice(0, i) : line).trim();
  return { name: name.slice(0, 100).replace(/[^\w\s!?.-]/g, "").trim() || "Topic", definition: (i > 0 ? line.slice(i + 1) : line).trim() || name, type: "DENY" as const };
}

type Strength = "NONE" | "LOW" | "MEDIUM" | "HIGH";

/** The policies of the guardrail sheet (create and edit share it). */
function guardrailConfig(form: FormData) {
  const strength = (name: string) => (text(form, name) || "NONE") as Strength;
  const filters = FILTERS.map((type) => ({
    type: type as GuardrailContentFilterType,
    inputStrength: strength(`in_${type}`),
    outputStrength: type === "PROMPT_ATTACK" ? ("NONE" as const) : strength(`out_${type}`),
  })).filter((f) => f.inputStrength !== "NONE" || f.outputStrength !== "NONE");
  const topics = text(form, "topics").split("\n").map((t) => t.trim()).filter(Boolean);
  const words = list(text(form, "words"));
  const profanity = text(form, "profanity") === "on";
  const pii = [...form.keys()]
    .filter((k) => k.startsWith("pii_") && text(form, k))
    .map((k) => ({ type: k.slice(4) as GuardrailPiiEntityType, action: text(form, k) as GuardrailSensitiveInformationAction }));
  const regexAction = (text(form, "regexAction") || "ANONYMIZE") as GuardrailSensitiveInformationAction;
  const regexes = text(form, "regexes")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf(":");
      if (i < 1) throw new FieldError("regexes", `"${l}" is not name: pattern`, "format");
      return { name: l.slice(0, i).trim(), pattern: l.slice(i + 1).trim(), action: regexAction };
    });
  const threshold = (name: string, type: GuardrailContextualGroundingFilterType) => {
    const v = text(form, name);
    return v === "" ? [] : [{ type, threshold: Number(v) }];
  };
  const grounding = [...threshold("grounding", "GROUNDING"), ...threshold("relevance", "RELEVANCE")];
  const blocked = text(form, "blocked") || "Sorry, I can't help with that.";
  return {
    name: required(form, "name", "Name"),
    description: text(form, "description") || undefined,
    blockedInputMessaging: blocked,
    blockedOutputsMessaging: text(form, "blockedOutput") || blocked,
    contentPolicyConfig: filters.length ? { filtersConfig: filters } : undefined,
    topicPolicyConfig: topics.length ? { topicsConfig: topics.map((t) => topic(t)) } : undefined,
    wordPolicyConfig:
      words.length || profanity
        ? { wordsConfig: words.length ? words.map((w) => ({ text: w })) : undefined, managedWordListsConfig: profanity ? [{ type: "PROFANITY" as const }] : undefined }
        : undefined,
    sensitiveInformationPolicyConfig: pii.length || regexes.length ? { piiEntitiesConfig: pii.length ? pii : undefined, regexesConfig: regexes.length ? regexes : undefined } : undefined,
    contextualGroundingPolicyConfig: grounding.length ? { filtersConfig: grounding } : undefined,
  };
}

const GUARDRAIL_FIELDS = {
  name: "name",
  description: "description",
  blockedInputMessaging: "blocked",
  blockedOutputsMessaging: "blockedOutput",
  "topicPolicyConfig.topicsConfig.name": "topics",
  "topicPolicyConfig.topicsConfig.definition": "topics",
  "wordPolicyConfig.wordsConfig.text": "words",
  "sensitiveInformationPolicyConfig.regexesConfig.name": "regexes",
  "sensitiveInformationPolicyConfig.regexesConfig.pattern": "regexes",
  "contextualGroundingPolicyConfig.filtersConfig.threshold": "grounding",
  kmsKeyId: "kms",
  tags: "tags",
};

/** `key=value` lines as Bedrock tags. */
function tagLines(form: FormData, field: string) {
  return text(form, field)
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf("=");
      if (i < 1) throw new FieldError(field, `"${l}" is not key=value`, "format");
      return { key: l.slice(0, i).trim(), value: l.slice(i + 1).trim() };
    });
}

export async function createGuardrail(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const tags = tagLines(form, "tags");
    const out = await (await bedrock()).send(
      new CreateGuardrailCommand({ ...guardrailConfig(form), kmsKeyId: text(form, "kms") || undefined, tags: tags.length ? tags : undefined }),
    );
    redirect(`/bedrock/guardrail?id=${out.guardrailId}`);
  }, { fields: GUARDRAIL_FIELDS });
}

export async function updateGuardrail(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await bedrock()).send(new UpdateGuardrailCommand({ guardrailIdentifier: id, ...guardrailConfig(form) }));
    return "Saved to the working draft";
  }, { revalidate: ["/bedrock/guardrail", "/bedrock/guardrails"], fields: GUARDRAIL_FIELDS });
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
    const tags = tagLines(form, "tags");
    await (await bedrock()).send(
      new CreateInferenceProfileCommand({
        inferenceProfileName: required(form, "name", "Name"),
        modelSource: { copyFrom: required(form, "source", "Model") },
        description: text(form, "description") || undefined,
        tags: tags.length ? tags : undefined,
      }),
    );
    return "Created";
  }, { revalidate: ["/bedrock/profiles"], fields: { inferenceProfileName: "name", "modelSource.copyFrom": "source", description: "description", tags: "tags", "tags.key": "tags", "tags.value": "tags" } });
}

export async function deleteProfile(arn: string, then: string) {
  return act(async () => {
    await (await bedrock()).send(new DeleteInferenceProfileCommand({ inferenceProfileIdentifier: arn }));
    if (then) redirect(then);
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
    const client = await bedrock();
    // Keep what the form does not show (the large-data bucket set through the SDK).
    const current = (await client.send(new GetModelInvocationLoggingConfigurationCommand({}))).loggingConfig;
    const on = (name: string) => text(form, name) === "on";
    await client.send(
      new PutModelInvocationLoggingConfigurationCommand({
        loggingConfig: {
          ...current,
          cloudWatchConfig: group && roleArn ? { ...current?.cloudWatchConfig, logGroupName: group, roleArn } : undefined,
          s3Config: bucket ? { ...current?.s3Config, bucketName: bucket, keyPrefix: text(form, "prefix") || undefined } : undefined,
          textDataDeliveryEnabled: on("text"),
          imageDataDeliveryEnabled: on("images"),
          embeddingDataDeliveryEnabled: on("embeddings"),
          videoDataDeliveryEnabled: on("video"),
          audioDataDeliveryEnabled: on("audio"),
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
      command: text(form, "command") || undefined,
      args: text(form, "args") ? text(form, "args").split(/\s+/).filter(Boolean) : undefined,
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
    [/^Command/, "command"],
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
