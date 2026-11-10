"use server";

import {
  CreateSecretCommand,
  DeleteSecretCommand,
  PutSecretValueCommand,
  RestoreSecretCommand,
  RotateSecretCommand,
  UpdateSecretCommand,
} from "@aws-sdk/client-secrets-manager";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { secrets } from "../../lib/clients";

// Members (and error codes) to the form fields they concern. A KMS key
// Secrets Manager can't use fails as EncryptionFailure; a name scheduled for
// deletion as InvalidRequestException.
const CREATE_FIELDS = { Name: "name", SecretString: "value", Description: "description", KmsKeyId: "kmsKeyId", EncryptionFailure: "kmsKeyId", InvalidRequestException: "name" };

export async function createSecret(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    await (await secrets()).send(
      new CreateSecretCommand({
        Name: name,
        SecretString: text(form, "value"),
        Description: text(form, "description") || undefined,
        KmsKeyId: text(form, "kmsKeyId") || undefined,
      }),
    );
    return `Created ${name}`;
  }, { revalidate: ["/secrets"], fields: CREATE_FIELDS });
}

export async function putValue(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await secrets()).send(new PutSecretValueCommand({ SecretId: id, SecretString: text(form, "value") }));
    return `Stored version ${out.VersionId}`;
  }, { revalidate: ["/secrets/secret"], fields: { SecretString: "value", EncryptionFailure: "value" } });
}

export async function updateSecret(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await secrets()).send(
      new UpdateSecretCommand({ SecretId: id, Description: text(form, "description"), KmsKeyId: text(form, "kmsKeyId") || undefined }),
    );
    return "Saved";
  }, { revalidate: ["/secrets/secret"], fields: { Description: "description", KmsKeyId: "kmsKeyId", EncryptionFailure: "kmsKeyId" } });
}

export async function rotate(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const lambda = text(form, "lambda");
    const days = Number(text(form, "days") || 0);
    const out = await (await secrets()).send(
      new RotateSecretCommand({
        SecretId: id,
        RotationLambdaARN: lambda || undefined,
        RotationRules: days ? { AutomaticallyAfterDays: days } : undefined,
      }),
    );
    return `Rotated to ${out.VersionId}`;
  }, {
    revalidate: ["/secrets/secret"],
    // AccessDenied here is the function policy not letting Secrets Manager
    // invoke it; InvalidParameter, rotation rules it rejects.
    fields: { RotationLambdaARN: "lambda", "RotationRules.AutomaticallyAfterDays": "days", AccessDeniedException: "lambda", InvalidParameterException: "days" },
  });
}

export async function restore(id: string) {
  return act(async () => {
    await (await secrets()).send(new RestoreSecretCommand({ SecretId: id }));
    return "Restored";
  }, "/secrets", "/secrets/secret");
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
