import "server-only";

import { BedrockClient } from "@aws-sdk/client-bedrock";
import { BedrockRuntimeClient } from "@aws-sdk/client-bedrock-runtime";
import { client } from "@mws-dashboard/aws";

export const bedrock = () => client(BedrockClient);
export const bedrockRuntime = () => client(BedrockRuntimeClient);

export const ICONS = {
  bedrock: "service/AmazonBedrock",
  model: "resource/AmazonSageMakerAIModel",
  guardrail: "resource/AWSIdentityAccessManagementPermissions",
};

export type Tone = "good" | "warn" | "bad" | "neutral" | "info";

/** Logos of model providers. */
export function providerIcon(provider: string | undefined): string | undefined {
  const p = (provider ?? "").toLowerCase();
  const logos: [string, string][] = [
    ["anthropic", "ai/claude"],
    ["amazon", "ai/nova"],
    ["meta", "ai/meta"],
    ["mistral", "ai/mistral"],
    ["deepseek", "ai/deepseek"],
    ["cohere", "ai/cohere"],
    ["openai", "ai/openai"],
    ["qwen", "ai/qwen"],
    ["stability", "ai/stability"],
    ["ai21", "ai/ai21"],
    ["luma", "ai/luma"],
    ["minimax", "ai/minimax"],
    ["moonshot", "ai/kimi"],
    ["google", "ai/gemini"],
  ];
  return logos.find(([k]) => p.includes(k))?.[1];
}

/** Words AWS uses for states, as tones. */
export function tone(status: string | undefined): Tone {
  const s = (status ?? "").toUpperCase();
  if (/PARTIAL|STOPPED|EXPIRED/.test(s)) return "warn";
  if (/FAIL|ERROR|CANCEL|UNHEALTHY|DEPRECATED|DELETED/.test(s)) return "bad";
  if (/PENDING|RUNNING|PROVISION|BUILD|CREAT|UPDAT|DELET|PROGRESS|TEST|DISTRIBUT|INTEGRAT|STARTING|CANCELLING|LEGACY/.test(s)) return "warn";
  if (/SUCCE|AVAILABLE|ACTIVE|HEALTHY|INSERVICE|COMPLETE|ENABLED|READY/.test(s)) return "good";
  return "neutral";
}
