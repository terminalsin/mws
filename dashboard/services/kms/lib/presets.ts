// The key types the create sheet opens on. Each fills the usage, spec and
// origin a common job needs; plain data, so the client form can import it.

export interface KeyPreset {
  id: string;
  label: string;
  title: string;
  usage: string;
  spec: string;
  origin: "AWS_KMS" | "EXTERNAL";
  /** The alias the form suggests (made unique). */
  alias: string;
}

export const KEY_PRESETS: KeyPreset[] = [
  { id: "encrypt", label: "Encrypt", title: "Symmetric AES-256: envelope encryption, S3, RDS, Secrets Manager", usage: "ENCRYPT_DECRYPT", spec: "SYMMETRIC_DEFAULT", origin: "AWS_KMS", alias: "app-data" },
  { id: "sign", label: "Sign", title: "Asymmetric signing and verification", usage: "SIGN_VERIFY", spec: "ECC_NIST_P256", origin: "AWS_KMS", alias: "signing" },
  { id: "mac", label: "HMAC", title: "Generate and verify message authentication codes", usage: "GENERATE_VERIFY_MAC", spec: "HMAC_256", origin: "AWS_KMS", alias: "hmac" },
  { id: "rsa", label: "RSA encrypt", title: "Public-key encryption: others encrypt with the public key", usage: "ENCRYPT_DECRYPT", spec: "RSA_2048", origin: "AWS_KMS", alias: "rsa-encrypt" },
  { id: "agreement", label: "Key agreement", title: "ECDH: derive shared secrets", usage: "KEY_AGREEMENT", spec: "ECC_NIST_P256", origin: "AWS_KMS", alias: "key-agreement" },
  { id: "pq", label: "Post-quantum", title: "ML-KEM key encapsulation", usage: "ENCAPSULATE_DECAPSULATE", spec: "ML_KEM_768", origin: "AWS_KMS", alias: "ml-kem" },
  { id: "import", label: "Import", title: "Symmetric key with key material you import", usage: "ENCRYPT_DECRYPT", spec: "SYMMETRIC_DEFAULT", origin: "EXTERNAL", alias: "imported" },
];
