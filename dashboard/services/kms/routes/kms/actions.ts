"use server";

import {
  CancelKeyDeletionCommand,
  CreateAliasCommand,
  CreateKeyCommand,
  DecryptCommand,
  DeleteAliasCommand,
  DisableKeyCommand,
  DisableKeyRotationCommand,
  EnableKeyCommand,
  EnableKeyRotationCommand,
  EncryptCommand,
  PutKeyPolicyCommand,
  ScheduleKeyDeletionCommand,
  SignCommand,
  TagResourceCommand,
  GenerateMacCommand,
  type KeySpec,
  type KeyUsageType,
  type SigningAlgorithmSpec,
  type MacAlgorithmSpec,
} from "@aws-sdk/client-kms";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { kms } from "../../lib/clients";

const page = (_id: string) => "/kms/key";

export async function createKey(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await kms();
    const spec = (text(form, "spec") || "SYMMETRIC_DEFAULT") as KeySpec;
    const usage: KeyUsageType =
      spec === "SYMMETRIC_DEFAULT" || (spec.startsWith("RSA") && text(form, "usage") !== "sign")
        ? "ENCRYPT_DECRYPT"
        : spec.startsWith("HMAC")
          ? "GENERATE_VERIFY_MAC"
          : "SIGN_VERIFY";
    const out = await client.send(
      new CreateKeyCommand({ KeySpec: spec, KeyUsage: usage, Description: text(form, "description") || undefined, MultiRegion: text(form, "multiRegion") === "on" }),
    );
    const id = out.KeyMetadata!.KeyId!;
    const alias = text(form, "alias");
    if (alias) await client.send(new CreateAliasCommand({ AliasName: alias.startsWith("alias/") ? alias : `alias/${alias}`, TargetKeyId: id }));
    if (spec === "SYMMETRIC_DEFAULT" && text(form, "rotation") === "on") await client.send(new EnableKeyRotationCommand({ KeyId: id }));
    return `Created ${alias || id}`;
  }, "/kms");
}

export async function setEnabled(keyId: string, enable: boolean) {
  return act(
    async () => {
      const client = await kms();
      if (enable) await client.send(new EnableKeyCommand({ KeyId: keyId }));
      else await client.send(new DisableKeyCommand({ KeyId: keyId }));
      return enable ? "Enabled" : "Disabled";
    },
    "/kms",
    page(keyId),
  );
}

export async function setRotation(keyId: string, enable: boolean) {
  return act(async () => {
    const client = await kms();
    if (enable) await client.send(new EnableKeyRotationCommand({ KeyId: keyId }));
    else await client.send(new DisableKeyRotationCommand({ KeyId: keyId }));
    return enable ? "Rotation on" : "Rotation off";
  }, page(keyId));
}

export async function scheduleDeletion(keyId: string, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const days = Number(text(form, "days") || 30);
      const out = await (await kms()).send(new ScheduleKeyDeletionCommand({ KeyId: keyId, PendingWindowInDays: days }));
      return `Deletes ${out.DeletionDate?.toISOString().slice(0, 10)}`;
    },
    "/kms",
    page(keyId),
  );
}

export async function cancelDeletion(keyId: string) {
  return act(
    async () => {
      await (await kms()).send(new CancelKeyDeletionCommand({ KeyId: keyId }));
      return "Deletion cancelled; the key is disabled";
    },
    "/kms",
    page(keyId),
  );
}

export async function addAlias(keyId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const alias = required(form, "alias", "Alias");
    await (await kms()).send(new CreateAliasCommand({ AliasName: alias.startsWith("alias/") ? alias : `alias/${alias}`, TargetKeyId: keyId }));
    return `Added ${alias}`;
  }, page(keyId));
}

export async function deleteAlias(keyId: string, alias: string) {
  return act(async () => {
    await (await kms()).send(new DeleteAliasCommand({ AliasName: alias }));
    return `Removed ${alias}`;
  }, page(keyId));
}

export async function saveKeyPolicy(keyId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Policy = required(form, "policy", "Policy");
    JSON.parse(Policy);
    await (await kms()).send(new PutKeyPolicyCommand({ KeyId: keyId, PolicyName: "default", Policy }));
    return "Key policy saved";
  }, page(keyId));
}

export async function saveKeyTags(keyId: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Tags = text(form, "tags")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => {
        const [TagKey, ...rest] = l.split("=");
        return { TagKey: TagKey.trim(), TagValue: rest.join("=").trim() };
      });
    await (await kms()).send(new TagResourceCommand({ KeyId: keyId, Tags }));
    return "Tags saved";
  }, page(keyId));
}

/** Use the key on a string: encrypt and decrypt, sign, or MAC, by its usage. */
export async function tryKey(keyId: string, usage: string, algorithm: string | undefined, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await kms();
    const input = new TextEncoder().encode(required(form, "plaintext", "Text"));
    if (usage === "SIGN_VERIFY") {
      const out = await client.send(
        new SignCommand({ KeyId: keyId, Message: input, MessageType: "RAW", SigningAlgorithm: algorithm as SigningAlgorithmSpec }),
      );
      return { ok: true, message: `Signed with ${out.SigningAlgorithm}`, detail: Buffer.from(out.Signature!).toString("base64") };
    }
    if (usage === "GENERATE_VERIFY_MAC") {
      const out = await client.send(new GenerateMacCommand({ KeyId: keyId, Message: input, MacAlgorithm: algorithm as MacAlgorithmSpec }));
      return { ok: true, message: out.MacAlgorithm!, detail: Buffer.from(out.Mac!).toString("base64") };
    }
    const encrypted = await client.send(new EncryptCommand({ KeyId: keyId, Plaintext: input }));
    const decrypted = await client.send(new DecryptCommand({ CiphertextBlob: encrypted.CiphertextBlob, KeyId: keyId }));
    return {
      ok: true,
      message: "Round trip ok",
      detail: `${Buffer.from(encrypted.CiphertextBlob!).toString("base64")}\n\n→ ${new TextDecoder().decode(decrypted.Plaintext)}`,
    };
  });
}

