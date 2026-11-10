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

/** Every `KeyUsageType`, in the order the list shows them. */
export const USAGE = [
  { id: "ENCRYPT_DECRYPT", title: "Encryption", verb: "Encrypt" },
  { id: "SIGN_VERIFY", title: "Signing", verb: "Sign and verify" },
  { id: "GENERATE_VERIFY_MAC", title: "MAC", verb: "Generate and verify MAC" },
  { id: "KEY_AGREEMENT", title: "Key agreement", verb: "Derive shared secret" },
  { id: "ENCAPSULATE_DECAPSULATE", title: "Key encapsulation", verb: "Encapsulate and decapsulate" },
] as const;

/** The key specs each usage allows (AWS's CreateKey rules). */
export const SPECS_FOR: Record<string, string[]> = {
  ENCRYPT_DECRYPT: ["SYMMETRIC_DEFAULT", "RSA_2048", "RSA_3072", "RSA_4096", "SM2"],
  SIGN_VERIFY: ["RSA_2048", "RSA_3072", "RSA_4096", "ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "ECC_SECG_P256K1", "ECC_NIST_EDWARDS25519", "ML_DSA_44", "ML_DSA_65", "ML_DSA_87", "SM2"],
  GENERATE_VERIFY_MAC: ["HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512"],
  KEY_AGREEMENT: ["ECC_NIST_P256", "ECC_NIST_P384", "ECC_NIST_P521", "SM2"],
  ENCAPSULATE_DECAPSULATE: ["ML_KEM_512", "ML_KEM_768", "ML_KEM_1024"],
};

export const ALL_SPECS = [...new Set(Object.values(SPECS_FOR).flat())];

/** The usage a spec gets when the form leaves it to the spec. */
export function defaultUsage(spec: string) {
  if (spec.startsWith("HMAC")) return "GENERATE_VERIFY_MAC";
  if (spec.startsWith("ML_KEM")) return "ENCAPSULATE_DECAPSULATE";
  if (spec === "SYMMETRIC_DEFAULT" || spec.startsWith("RSA") || spec === "SM2") return "ENCRYPT_DECRYPT";
  return "SIGN_VERIFY";
}

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
