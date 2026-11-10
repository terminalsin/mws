import "server-only";

import { CodeartifactClient } from "@aws-sdk/client-codeartifact";
import { client } from "@mws-dashboard/aws";

export const codeartifact = () => client(CodeartifactClient);

export const ICONS = {
  codeartifact: "service/AWSCodeArtifact",
};

export type Tone = "good" | "warn" | "bad" | "neutral" | "info";

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
