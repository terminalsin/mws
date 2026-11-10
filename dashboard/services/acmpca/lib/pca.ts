export const CA_TONE: Record<string, "good" | "warn" | "bad" | "neutral" | "info"> = {
  ACTIVE: "good",
  PENDING_CERTIFICATE: "warn",
  CREATING: "info",
  DISABLED: "neutral",
  DELETED: "bad",
  EXPIRED: "bad",
  FAILED: "bad",
};

export const KEY_ALGORITHMS = ["RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1", "ML_DSA_44", "ML_DSA_65", "ML_DSA_87"] as const;

/** The signing algorithm a key signs with by default. */
export const DEFAULT_SIGNING: Record<string, string> = {
  RSA_2048: "SHA256WITHRSA",
  RSA_3072: "SHA384WITHRSA",
  RSA_4096: "SHA512WITHRSA",
  EC_prime256v1: "SHA256WITHECDSA",
  EC_secp384r1: "SHA384WITHECDSA",
  EC_secp521r1: "SHA512WITHECDSA",
  ML_DSA_44: "ML_DSA_44",
  ML_DSA_65: "ML_DSA_65",
  ML_DSA_87: "ML_DSA_87",
  SM2: "SM3WITHSM2",
};

const SIGNING = ["SHA256WITHRSA", "SHA384WITHRSA", "SHA512WITHRSA", "SHA256WITHRSA_PSS", "SHA384WITHRSA_PSS", "SHA512WITHRSA_PSS", "SHA256WITHECDSA", "SHA384WITHECDSA", "SHA512WITHECDSA"];

/** The signing algorithms a CA's key can sign with (its key family's). */
export function signingFor(key: string | undefined) {
  if (!key) return ["SHA256WITHRSA"];
  if (key.startsWith("ML_DSA")) return [key];
  if (key === "SM2") return ["SM3WITHSM2"];
  const family = key.startsWith("EC_") ? "ECDSA" : "RSA";
  return SIGNING.filter((s) => s.endsWith(`WITH${family}`) || (family === "RSA" && s.endsWith("WITHRSA_PSS")));
}

/** Issuance templates the issue form offers. */
export const TEMPLATES = [
  { id: "EndEntityCertificate/V1", label: "End entity" },
  { id: "EndEntityClientAuthCertificate/V1", label: "Client authentication" },
  { id: "EndEntityServerAuthCertificate/V1", label: "Server authentication" },
  { id: "CodeSigningCertificate/V1", label: "Code signing" },
  { id: "OCSPSigningCertificate/V1", label: "OCSP signing" },
  { id: "BlankEndEntityCertificate_APIPassthrough/V1", label: "Blank end entity (passthrough)" },
] as const;

export const caName = (c: { Arn?: string; CertificateAuthorityConfiguration?: { Subject?: { CommonName?: string } } }) =>
  c.CertificateAuthorityConfiguration?.Subject?.CommonName ?? c.Arn?.split("/").pop() ?? "";

export const DAY = 86_400_000;

/** What a new CA usually is. Picking one sets its type, mode and key. */
export const CA_PRESETS = [
  { id: "root", label: "Root", icon: "resource/AWSCertificateManagerCertificateAuthority", type: "ROOT", usage: "GENERAL_PURPOSE", key: "RSA_2048", cn: "Root CA" },
  { id: "subordinate", label: "Issuing", title: "Subordinate CA, signed by a root", icon: "lucide:git-branch", type: "SUBORDINATE", usage: "GENERAL_PURPOSE", key: "RSA_2048", cn: "Issuing CA" },
  { id: "short-lived", label: "Short-lived", title: "Certificates valid up to 7 days, at a lower price", icon: "lucide:timer", type: "ROOT", usage: "SHORT_LIVED_CERTIFICATE", key: "EC_prime256v1", cn: "Short-lived CA" },
  { id: "post-quantum", label: "Post-quantum", title: "ML-DSA keys", icon: "lucide:atom", type: "ROOT", usage: "GENERAL_PURPOSE", key: "ML_DSA_65", cn: "PQ Root CA" },
] as const;

export type CaPreset = (typeof CA_PRESETS)[number];

/** Issuance templates as tiles. */
export const TEMPLATE_ICONS: Record<string, string> = {
  "EndEntityCertificate/V1": "lucide:badge-check",
  "EndEntityClientAuthCertificate/V1": "lucide:user-round",
  "EndEntityServerAuthCertificate/V1": "lucide:server",
  "CodeSigningCertificate/V1": "lucide:file-code",
  "OCSPSigningCertificate/V1": "lucide:radio-tower",
  "BlankEndEntityCertificate_APIPassthrough/V1": "lucide:file",
};

export const keyLabel = (k: string) => k.replace(/_/g, " ").replace("EC prime256v1", "ECDSA P-256").replace("EC secp384r1", "ECDSA P-384").replace("EC secp521r1", "ECDSA P-521");
