"use server";

import { CreateSecretCommand, DeleteSecretCommand, PutSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { secrets } from "../../lib/clients";

export async function createSecret(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Name");
    await (await secrets()).send(
      new CreateSecretCommand({ Name: name, SecretString: text(form, "value"), Description: text(form, "description") || undefined }),
    );
    return `Created secret ${name}`;
  }, "/secrets");
}

export async function putValue(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const out = await (await secrets()).send(new PutSecretValueCommand({ SecretId: id, SecretString: text(form, "value") }));
    return `Stored version ${out.VersionId}`;
  }, "/secrets/secret");
}

export async function deleteSecret(id: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const force = text(form, "force") === "on";
    await (await secrets()).send(
      new DeleteSecretCommand({ SecretId: id, ...(force ? { ForceDeleteWithoutRecovery: true } : { RecoveryWindowInDays: 7 }) }),
    );
    redirect("/secrets");
  });
}
