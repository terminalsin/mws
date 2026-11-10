"use server";

import {
  CancelRotateSecretCommand,
  CreateSecretCommand,
  DeleteResourcePolicyCommand,
  DeleteSecretCommand,
  PutResourcePolicyCommand,
  PutSecretValueCommand,
  RemoveRegionsFromReplicationCommand,
  ReplicateSecretToRegionsCommand,
  RestoreSecretCommand,
  RotateSecretCommand,
  StopReplicationToReplicaCommand,
  TagResourceCommand,
  UntagResourceCommand,
  UpdateSecretCommand,
  UpdateSecretVersionStageCommand,
  ValidateResourcePolicyCommand,
} from "@aws-sdk/client-secrets-manager";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { listItems } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { secrets } from "../../lib/clients";

const PAGE = "/secrets/secret";

// Members (and error codes) to the form fields they concern. A KMS key
// Secrets Manager can't use fails as EncryptionFailure; a name scheduled for
// deletion as InvalidRequestException.
const CREATE_FIELDS = {
  Name: "name",
  SecretString: "value",
  Description: "description",
  KmsKeyId: "kmsKeyId",
  EncryptionFailure: "kmsKeyId",
  InvalidRequestException: "name",
  Tags: "tags",
  AddReplicaRegions: "regions",
};

/** `key=value` lines as Secrets Manager tags. */
function tags(form: FormData, name = "tags") {
  return text(form, name)
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i) => {
      const [Key, ...rest] = l.split("=");
      if (!rest.length || !Key.trim()) throw new FieldError(name, `Line ${i + 1}: key=value`, "format");
      return { Key: Key.trim(), Value: rest.join("=").trim() };
    });
}

export async function createSecret(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    const Tags = tags(form);
    const regions = listItems(text(form, "regions"));
    await (await secrets()).send(
      new CreateSecretCommand({
        Name: name,
        SecretString: text(form, "value"),
        Description: text(form, "description") || undefined,
        KmsKeyId: text(form, "kmsKeyId") || undefined,
        Tags: Tags.length ? Tags : undefined,
        AddReplicaRegions: regions.length ? regions.map((Region) => ({ Region })) : undefined,
        ForceOverwriteReplicaSecret: regions.length ? text(form, "overwrite") === "on" : undefined,
      }),
    );
    return `Created ${name}`;
  }, { revalidate: ["/secrets"], fields: CREATE_FIELDS });
}

export async function putValue(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await secrets()).send(new PutSecretValueCommand({ SecretId: id, SecretString: text(form, "value") }));
    return `Stored version ${out.VersionId}`;
  }, { revalidate: [PAGE], fields: { SecretString: "value", EncryptionFailure: "value" } });
}

export async function updateSecret(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await secrets()).send(
      new UpdateSecretCommand({ SecretId: id, Description: text(form, "description"), KmsKeyId: text(form, "kmsKeyId") || undefined }),
    );
    return "Saved";
  }, { revalidate: ["/secrets", PAGE], fields: { Description: "description", KmsKeyId: "kmsKeyId", EncryptionFailure: "kmsKeyId", KMSInvalidStateException: "kmsKeyId" } });
}

/** Turn rotation on or change it: the function, the schedule (every N days,
 * or a `rate()`/`cron()` expression), its window, and whether to rotate now. */
export async function rotate(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const lambda = text(form, "lambda");
    const days = Number(text(form, "days") || 0);
    const expression = text(form, "expression");
    const duration = text(form, "duration");
    if (days && expression) throw new FieldError("expression", "Use either days or a schedule expression");
    const now = text(form, "immediately") === "on";
    const out = await (await secrets()).send(
      new RotateSecretCommand({
        SecretId: id,
        RotationLambdaARN: lambda || undefined,
        RotationRules:
          days || expression || duration
            ? { ...(days ? { AutomaticallyAfterDays: days } : {}), ...(expression ? { ScheduleExpression: expression } : {}), ...(duration ? { Duration: duration } : {}) }
            : undefined,
        RotateImmediately: now,
      }),
    );
    return now ? `Rotating to ${out.VersionId}` : "Rotation scheduled";
  }, {
    revalidate: [PAGE],
    // AccessDenied here is the function policy not letting Secrets Manager
    // invoke it; InvalidParameter, rotation rules it rejects.
    fields: {
      RotationLambdaARN: "lambda",
      "RotationRules.AutomaticallyAfterDays": "days",
      "RotationRules.ScheduleExpression": "expression",
      "RotationRules.Duration": "duration",
      AccessDeniedException: "lambda",
      InvalidParameterException: "days",
    },
  });
}

/** Rotate once, now, with the rotation already configured. */
export async function rotateNow(id: string) {
  return act(async () => {
    const out = await (await secrets()).send(new RotateSecretCommand({ SecretId: id }));
    return `Rotating to ${out.VersionId}`;
  }, PAGE);
}

export async function cancelRotation(id: string) {
  return act(async () => {
    await (await secrets()).send(new CancelRotateSecretCommand({ SecretId: id }));
    return "Rotation turned off";
  }, "/secrets", PAGE);
}

/** Move a staging label to `to` (from wherever it is, `from`). */
export async function moveStage(id: string, stage: string, to: string, from: string | undefined) {
  return act(async () => {
    await (await secrets()).send(new UpdateSecretVersionStageCommand({ SecretId: id, VersionStage: stage, MoveToVersionId: to, RemoveFromVersionId: from }));
    return `${stage} moved`;
  }, PAGE);
}

export async function removeStage(id: string, stage: string, from: string) {
  return act(async () => {
    await (await secrets()).send(new UpdateSecretVersionStageCommand({ SecretId: id, VersionStage: stage, RemoveFromVersionId: from }));
    return `${stage} removed`;
  }, PAGE);
}

/** Attach a label to a version; a label held by another version moves. */
export async function addStage(id: string, version: string, holders: Record<string, string>, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const stage = required(form, "stage", "Label");
    await (await secrets()).send(new UpdateSecretVersionStageCommand({ SecretId: id, VersionStage: stage, MoveToVersionId: version, RemoveFromVersionId: holders[stage] }));
    return `Labelled ${stage}`;
  }, { revalidate: [PAGE], fields: { VersionStage: "stage", InvalidParameterException: "stage", LimitExceededException: "stage" } });
}

export async function addReplicas(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const regions = listItems(required(form, "regions", "Regions"));
    const KmsKeyId = text(form, "kmsKeyId") || undefined;
    const out = await (await secrets()).send(
      new ReplicateSecretToRegionsCommand({
        SecretId: id,
        AddReplicaRegions: regions.map((Region) => ({ Region, KmsKeyId })),
        ForceOverwriteReplicaSecret: text(form, "overwrite") === "on",
      }),
    );
    const failed = (out.ReplicationStatus ?? []).filter((r) => r.Status === "Failed");
    if (failed.length) throw new FieldError("regions", failed.map((r) => `${r.Region}: ${r.StatusMessage}`).join("; "));
    return `Replicating to ${regions.join(", ")}`;
  }, { revalidate: [PAGE], fields: { AddReplicaRegions: "regions", "AddReplicaRegions.Region": "regions", KmsKeyId: "kmsKeyId", InvalidParameterException: "regions" } });
}

export async function removeReplica(id: string, region: string) {
  return act(async () => {
    await (await secrets()).send(new RemoveRegionsFromReplicationCommand({ SecretId: id, RemoveReplicaRegions: [region] }));
    return `Replica in ${region} removed`;
  }, PAGE);
}

/** Promote this replica to a standalone secret. */
export async function promote(id: string) {
  return act(async () => {
    await (await secrets()).send(new StopReplicationToReplicaCommand({ SecretId: id }));
    return "Promoted to a standalone secret";
  }, "/secrets", PAGE);
}

const POLICY_FIELDS = { ResourcePolicy: "policy", MalformedPolicyDocumentException: "policy", PublicPolicyException: "policy" };

export async function savePolicy(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const ResourcePolicy = required(form, "policy", "Policy");
    await (await secrets()).send(new PutResourcePolicyCommand({ SecretId: id, ResourcePolicy, BlockPublicPolicy: text(form, "block") === "on" }));
    return "Resource policy saved";
  }, { revalidate: [PAGE], fields: POLICY_FIELDS });
}

export async function validatePolicy(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await secrets()).send(new ValidateResourcePolicyCommand({ SecretId: id, ResourcePolicy: required(form, "policy", "Policy") }));
    const errors = out.ValidationErrors ?? [];
    if (!out.PolicyValidationPassed || errors.length)
      throw new FieldError("policy", errors.map((e) => `${e.CheckName}: ${e.ErrorMessage}`).join("; ") || "Validation failed");
    return "Policy passes validation";
  }, { fields: POLICY_FIELDS });
}

export async function deletePolicy(id: string) {
  return act(async () => {
    await (await secrets()).send(new DeleteResourcePolicyCommand({ SecretId: id }));
    return "Resource policy deleted";
  }, PAGE);
}

export async function saveTags(id: string, before: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await secrets();
    const Tags = tags(form);
    const gone = before.filter((k) => !Tags.some((t) => t.Key === k));
    if (gone.length) await client.send(new UntagResourceCommand({ SecretId: id, TagKeys: gone }));
    if (Tags.length) await client.send(new TagResourceCommand({ SecretId: id, Tags }));
    return "Tags saved";
  }, { revalidate: ["/secrets", PAGE], fields: { Tags: "tags", TagKeys: "tags" } });
}

export async function restore(id: string) {
  return act(async () => {
    await (await secrets()).send(new RestoreSecretCommand({ SecretId: id }));
    return "Restored";
  }, "/secrets", PAGE);
}

export async function deleteSecret(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const force = text(form, "force") === "on";
    await (await secrets()).send(
      new DeleteSecretCommand({ SecretId: id, ...(force ? { ForceDeleteWithoutRecovery: true } : { RecoveryWindowInDays: Number(text(form, "days") || 30) }) }),
    );
    redirect("/secrets");
  }, { fields: { RecoveryWindowInDays: "days" } });
}
