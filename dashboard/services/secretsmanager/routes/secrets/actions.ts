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
  }, "/secrets");
}

export async function putValue(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await secrets()).send(new PutSecretValueCommand({ SecretId: id, SecretString: text(form, "value") }));
    return `Stored version ${out.VersionId}`;
  }, "/secrets/secret");
}

export async function updateSecret(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await secrets()).send(
      new UpdateSecretCommand({ SecretId: id, Description: text(form, "description"), KmsKeyId: text(form, "kmsKeyId") || undefined }),
    );
    return "Saved";
  }, "/secrets/secret");
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
  }, "/secrets/secret");
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
  });
}
