// Key usages and the specs each allows: plain data, so client forms can use it too.

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
