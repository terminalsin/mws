import "server-only";

import { DescribeKeyCommand, ListAliasesCommand, ListKeysCommand } from "@aws-sdk/client-kms";
import { all } from "@mws-dashboard/aws";
import type { Tone } from "@mws-dashboard/ui";

import { kms } from "./clients";

export const STATE_TONE: Record<string, Tone> = {
  Enabled: "good",
  Disabled: "neutral",
  PendingDeletion: "bad",
  PendingReplicaDeletion: "bad",
  PendingImport: "warn",
  Unavailable: "bad",
  Creating: "info",
  Updating: "info",
};

/** States KMS moves out of on its own: the page refreshes while a key is in one. */
export const MOVING = new Set(["Creating", "Updating", "PendingReplicaDeletion"]);

export { ALL_SPECS, SPECS_FOR, USAGE, defaultUsage } from "./specs";

/** What a grant may allow on a key, by the key's usage (CreateGrant refuses the rest). */
export function grantOperations(usage: string | undefined, symmetric: boolean) {
  const common = ["DescribeKey", "CreateGrant", "RetireGrant"];
  switch (usage) {
    case "SIGN_VERIFY":
      return ["Sign", "Verify", "GetPublicKey", ...common];
    case "GENERATE_VERIFY_MAC":
      return ["GenerateMac", "VerifyMac", ...common];
    case "KEY_AGREEMENT":
      return ["DeriveSharedSecret", "GetPublicKey", ...common];
    case "ENCAPSULATE_DECAPSULATE":
      return ["Decapsulate", "GetPublicKey", ...common];
    default:
      return symmetric
        ? ["Encrypt", "Decrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateDataKeyPair", "GenerateDataKeyPairWithoutPlaintext", "ReEncryptFrom", "ReEncryptTo", ...common]
        : ["Encrypt", "Decrypt", "ReEncryptFrom", "ReEncryptTo", "GetPublicKey", ...common];
  }
}

/** Every alias in the account and Region, AWS managed ones included. */
export async function listAliases() {
  const client = await kms();
  return all((Marker) => client.send(new ListAliasesCommand({ Marker })), (r) => r.Aliases, (r) => (r.Truncated ? r.NextMarker : undefined));
}

export async function listKeys() {
  const client = await kms();
  const [list, aliases] = await Promise.all([
    all((Marker) => client.send(new ListKeysCommand({ Marker })), (r) => r.Keys, (r) => (r.Truncated ? r.NextMarker : undefined)),
    listAliases(),
  ]);
  const described = await Promise.all(list.map(async (k) => (await client.send(new DescribeKeyCommand({ KeyId: k.KeyId! }))).KeyMetadata!));
  return described.map((meta) => ({ meta, aliases: aliases.filter((a) => a.TargetKeyId === meta.KeyId).map((a) => a.AliasName!) }));
}

/** DER (SubjectPublicKeyInfo) as PEM. */
export function pem(der: Uint8Array, label = "PUBLIC KEY") {
  const b64 = Buffer.from(der).toString("base64");
  return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----`;
}
