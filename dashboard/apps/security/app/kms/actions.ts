"use server";

import {
  CreateAliasCommand,
  CreateKeyCommand,
  DecryptCommand,
  DisableKeyCommand,
  EnableKeyCommand,
  EncryptCommand,
  ScheduleKeyDeletionCommand,
  type KeySpec,
  type KeyUsageType,
} from "@aws-sdk/client-kms";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";

import { kms } from "../../lib/clients";

export async function createKey(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await kms();
    const spec = (text(form, "spec") || "SYMMETRIC_DEFAULT") as KeySpec;
    const usage: KeyUsageType = spec === "SYMMETRIC_DEFAULT" || spec.startsWith("RSA") ? "ENCRYPT_DECRYPT" : spec.startsWith("HMAC") ? "GENERATE_VERIFY_MAC" : "SIGN_VERIFY";
    const out = await client.send(new CreateKeyCommand({ KeySpec: spec, KeyUsage: usage, Description: text(form, "description") || undefined }));
    const alias = text(form, "alias");
    if (alias) {
      await client.send(new CreateAliasCommand({ AliasName: alias.startsWith("alias/") ? alias : `alias/${alias}`, TargetKeyId: out.KeyMetadata!.KeyId! }));
    }
    return `Created key ${out.KeyMetadata!.KeyId}`;
  }, "/kms");
}

export async function setEnabled(keyId: string, enable: boolean) {
  return act(async () => {
    const client = await kms();
    await client.send(enable ? new EnableKeyCommand({ KeyId: keyId }) : new DisableKeyCommand({ KeyId: keyId }));
    return enable ? "Enabled" : "Disabled";
  }, "/kms");
}

export async function scheduleDeletion(keyId: string) {
  return act(async () => {
    const out = await (await kms()).send(new ScheduleKeyDeletionCommand({ KeyId: keyId, PendingWindowInDays: 7 }));
    return `Deletion scheduled for ${out.DeletionDate?.toISOString()}`;
  }, "/kms");
}

/** Round-trip a string through the key, to check it works and see the ciphertext. */
export async function tryEncrypt(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await kms();
    const KeyId = required(form, "keyId", "Key");
    const encrypted = await client.send(new EncryptCommand({ KeyId, Plaintext: new TextEncoder().encode(required(form, "plaintext", "Plaintext")) }));
    const decrypted = await client.send(new DecryptCommand({ CiphertextBlob: encrypted.CiphertextBlob }));
    return {
      ok: true,
      message: `Encrypted with ${encrypted.KeyId} and decrypted again`,
      detail: `Ciphertext (base64):\n${Buffer.from(encrypted.CiphertextBlob!).toString("base64")}\n\nDecrypted:\n${new TextDecoder().decode(decrypted.Plaintext)}`,
    };
  });
}
