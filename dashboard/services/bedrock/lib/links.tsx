import { AwsIcon, Segments } from "@mws-dashboard/ui";
import Link from "next/link";
import type { ReactNode } from "react";

/** The console page of an `s3://bucket/prefix` URI. */
export function s3Href(uri: string | undefined): string | undefined {
  const m = uri?.match(/^s3:\/\/([^/]+)\/?(.*)$/);
  if (!m) return undefined;
  const [, bucket, rest] = m;
  if (!rest) return `/s3/${bucket}`;
  // A key ends in a file name; a prefix in "/".
  if (/\/$/.test(rest) || !/\.[a-z0-9]{1,6}$/i.test(rest)) return `/s3/${bucket}?prefix=${encodeURIComponent(rest.endsWith("/") ? rest : `${rest}/`)}`;
  return `/s3/${bucket}/object?key=${encodeURIComponent(rest)}`;
}

export function S3Link({ uri }: { uri: string | undefined }) {
  if (!uri) return null;
  const href = s3Href(uri);
  return href ? <Link href={href}>{uri}</Link> : <code>{uri}</code>;
}

export function RoleLink({ arn }: { arn: string | undefined }) {
  if (!arn) return null;
  const name = arn.split("/").pop() ?? arn;
  return (
    <Link href={`/iam/roles/${encodeURIComponent(name)}`} className="inline-icon">
      <AwsIcon icon="resource/AWSIdentityAccessManagementRole" size={14} /> {name}
    </Link>
  );
}

export function KmsLink({ arn }: { arn: string | undefined }) {
  if (!arn) return null;
  return <Link href={`/kms/key?id=${encodeURIComponent(arn)}`}>{arn.split("/").pop()}</Link>;
}

/** Where a model ARN or id points in this console. */
export function modelHref(arn: string | undefined): string | undefined {
  if (!arn) return undefined;
  if (arn.includes(":custom-model/")) return `/bedrock/custom-model?arn=${encodeURIComponent(arn)}`;
  if (arn.includes(":provisioned-model/")) return `/bedrock/provisioned-model?arn=${encodeURIComponent(arn)}`;
  if (arn.includes("inference-profile/")) return `/bedrock/profile?id=${encodeURIComponent(arn)}`;
  return undefined;
}

/** A model reference, shortened to its id, linked when it has a page. */
export function ModelRef({ arn }: { arn: string | undefined }): ReactNode {
  if (!arn) return null;
  const short = arn.includes(":foundation-model/") ? arn.split("/").pop() : arn.includes(":custom-model/") ? arn.split("/").slice(1).join("/") : arn.split("/").pop();
  const href = modelHref(arn);
  return href ? <Link href={href}>{short}</Link> : <code>{short}</code>;
}

/** Bedrock's "Infer" pages, as tabs. */
export function InferTabs({ active }: { active: "provisioned" | "batch" | "async" }) {
  return (
    <Segments
      label="Inference"
      items={[
        { label: "Provisioned Throughput", href: "/bedrock/provisioned", active: active === "provisioned" },
        { label: "Batch inference", href: "/bedrock/batch", active: active === "batch" },
        { label: "Async invocations", href: "/bedrock/async", active: active === "async" },
      ]}
    />
  );
}

/** States a job, invocation or resource is still changing from, so the page
 * keeps refreshing (`Status` only knows "-ing" words). */
export const RUNNING = /^(Submitted|Scheduled|Validating|InProgress|Stopping|Creating|Updating)$/;

export const TYPE_LABEL: Record<string, string> = {
  FINE_TUNING: "Fine-tuning",
  CONTINUED_PRE_TRAINING: "Continued pre-training",
  DISTILLATION: "Distillation",
  REINFORCEMENT_FINE_TUNING: "Reinforcement fine-tuning",
  IMPORTED: "Imported",
};
