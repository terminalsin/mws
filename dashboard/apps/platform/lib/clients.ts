import "server-only";

import { AmplifyClient } from "@aws-sdk/client-amplify";
import { AutoScalingClient } from "@aws-sdk/client-auto-scaling";
import { BedrockClient } from "@aws-sdk/client-bedrock";
import { BedrockRuntimeClient } from "@aws-sdk/client-bedrock-runtime";
import { CodeartifactClient } from "@aws-sdk/client-codeartifact";
import { EC2Client } from "@aws-sdk/client-ec2";
import { IAMClient } from "@aws-sdk/client-iam";
import { MarketplaceMeteringClient } from "@aws-sdk/client-marketplace-metering";
import { ImagebuilderClient } from "@aws-sdk/client-imagebuilder";
import { client } from "@mws-dashboard/aws";

export const bedrock = () => client(BedrockClient);
export const bedrockRuntime = () => client(BedrockRuntimeClient);
export const amplify = () => client(AmplifyClient);
export const codeartifact = () => client(CodeartifactClient);
export const imagebuilder = () => client(ImagebuilderClient);
export const autoscaling = () => client(AutoScalingClient);
export const ec2 = () => client(EC2Client);

export const ICONS = {
  bedrock: "service/AmazonBedrock",
  model: "resource/AmazonSageMakerAIModel",
  guardrail: "resource/AWSIdentityAccessManagementPermissions",
  amplify: "service/AWSAmplify",
  codeartifact: "service/AWSCodeArtifact",
  imagebuilder: "service/AmazonEC2ImageBuilder",
  ami: "resource/AmazonEC2AMI",
  instance: "resource/AmazonEC2Instance",
  autoscaling: "service/AmazonEC2AutoScaling",
  asg: "resource/AmazonEC2AutoScaling",
  marketplace: "service/AWSMarketplace",
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

/** CodeArtifact package formats and their ecosystems' logos. */
export const FORMAT_ICONS: Record<string, string> = {
  npm: "brand/npm",
  pypi: "brand/pypi",
  maven: "brand/apachemaven",
  cargo: "brand/rust",
  ruby: "brand/rubygems",
  nuget: "brand/nuget",
  swift: "brand/swift",
  generic: "resource/AmazonSimpleStorageServiceObject",
};

/** Words AWS uses for states, as tones. */
export function tone(status: string | undefined): Tone {
  const s = (status ?? "").toUpperCase();
  if (/FAIL|ERROR|CANCEL|UNHEALTHY|DEPRECATED|DELETED/.test(s)) return "bad";
  if (/PENDING|RUNNING|PROVISION|BUILD|CREAT|UPDAT|DELET|PROGRESS|TEST|DISTRIBUT|INTEGRAT|STARTING|CANCELLING|LEGACY/.test(s)) return "warn";
  if (/SUCCE|AVAILABLE|ACTIVE|HEALTHY|INSERVICE|COMPLETE|ENABLED|READY/.test(s)) return "good";
  return "neutral";
}
export const iam = () => client(IAMClient);
export const metering = () => client(MarketplaceMeteringClient);
