import "server-only";

import { ListCertificatesCommand } from "@aws-sdk/client-acm";
import { collect } from "@mws-dashboard/aws";

import { acm } from "./clients";

export const CERT_TONE: Record<string, "good" | "warn" | "bad" | "neutral"> = {
  ISSUED: "good",
  PENDING_VALIDATION: "warn",
  INACTIVE: "neutral",
  EXPIRED: "bad",
  VALIDATION_TIMED_OUT: "bad",
  REVOKED: "bad",
  FAILED: "bad",
};

export const KEY_TYPES = ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"] as const;

export async function listCertificates() {
  const client = await acm();
  return collect(
    (NextToken) => client.send(new ListCertificatesCommand({ NextToken, Includes: { keyTypes: [...KEY_TYPES] } })),
    (r) => r.CertificateSummaryList,
    (r) => r.NextToken,
  );
}

export const statusText = (s: string | undefined) => (s ? s[0] + s.slice(1).toLowerCase().replace(/_/g, " ") : "");
