// What KMS's forms check before they submit, on top of the model's rules.
import type { Rule } from "@mws-dashboard/ui";
import { CreateAlias, CreateKey, Encrypt, GenerateMac, PutKeyPolicy, ScheduleKeyDeletion, Sign } from "@mws-dashboard/ui/model/kms";

/** An alias, with or without its `alias/` prefix (the actions add it). */
export const ALIAS: Rule = {
  ...CreateAlias.AliasName,
  pattern: "^(alias/)?[a-zA-Z0-9:/_-]+$",
  hint: "Letters, digits, / _ - and :",
  reserved: ["alias/aws/", "aws/"],
  generate: "name",
};

/** The names an alias field must avoid, both with and without the prefix. */
export const takenAliases = (names: string[]) => names.flatMap((n) => [n, n.replace(/^alias\//, "")]);

export const DESCRIPTION: Rule = CreateKey.Description;

/** KMS takes 1–365 in its model but only allows 7–30 days. */
export const PENDING_DAYS: Rule = { ...ScheduleKeyDeletion.PendingWindowInDays, min: 7, max: 30, default: 30 };

export const POLICY: Rule = { ...PutKeyPolicy.Policy, format: "policy" };

export const TAGS: Rule = { format: "tags" };

/** RSA encryption takes far less than the model's 4096 bytes: the key size
 * minus the OAEP padding. */
const RSA_OAEP_MAX: Record<string, Record<string, number>> = {
  RSAES_OAEP_SHA_1: { RSA_2048: 214, RSA_3072: 342, RSA_4096: 470 },
  RSAES_OAEP_SHA_256: { RSA_2048: 190, RSA_3072: 318, RSA_4096: 446 },
};

/** The input of the key's try-it form, by what the key does. */
export function messageRule(usage: string, spec: string, algorithm: string | undefined): Rule {
  const base = usage === "SIGN_VERIFY" ? Sign.Message : usage === "GENERATE_VERIFY_MAC" ? GenerateMac.Message : Encrypt.Plaintext;
  const rsa = algorithm ? RSA_OAEP_MAX[algorithm]?.[spec] : undefined;
  return { ...base, type: "string", maxLength: rsa ?? base.maxLength };
}

/** The algorithm the try-it form uses: the key's first signing or MAC
 * algorithm, or for RSA encryption OAEP with SHA-256. */
export function tryAlgorithm(meta: { SigningAlgorithms?: string[]; MacAlgorithms?: string[]; EncryptionAlgorithms?: string[] }) {
  const enc = meta.EncryptionAlgorithms ?? [];
  return meta.SigningAlgorithms?.[0] ?? meta.MacAlgorithms?.[0] ?? (enc.includes("RSAES_OAEP_SHA_256") ? "RSAES_OAEP_SHA_256" : enc[0]);
}
