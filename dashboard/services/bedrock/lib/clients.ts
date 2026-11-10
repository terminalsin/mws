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

/** Logos of model providers that have one. */
export function providerIcon(provider: string | undefined): string | undefined {
  const p = (provider ?? "").toLowerCase();
  if (p.includes("anthropic")) return "brand/anthropic";
  if (p.includes("meta")) return "brand/meta";
  if (p.includes("mistral")) return "brand/mistralai";
  if (p.includes("deepseek")) return "brand/deepseek";
  return undefined;
}

/** Words AWS uses for states, as tones. */
export function tone(status: string | undefined): Tone {
  const s = (status ?? "").toUpperCase();
  if (/FAIL|ERROR|CANCEL|UNHEALTHY|DEPRECATED|DELETED/.test(s)) return "bad";
  if (/PENDING|RUNNING|PROVISION|BUILD|CREAT|UPDAT|DELET|PROGRESS|TEST|DISTRIBUT|INTEGRAT|STARTING|CANCELLING|LEGACY/.test(s)) return "warn";
  if (/SUCCE|AVAILABLE|ACTIVE|HEALTHY|INSERVICE|COMPLETE|ENABLED|READY/.test(s)) return "good";
  return "neutral";
}
