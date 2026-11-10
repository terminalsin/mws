import "server-only";

import { ListCertificateAuthoritiesCommand } from "@aws-sdk/client-acm-pca";
import { type InventoryItem } from "@mws-dashboard/aws";

import { pca } from "./clients";

export async function authorities(): Promise<InventoryItem[]> {
  const out = await (await pca()).send(new ListCertificateAuthoritiesCommand({}));
  return (out.CertificateAuthorities ?? []).map((c) => ({
    service: "acmpca",
    type: "Certificate authority",
    id: c.Arn!,
    name: c.CertificateAuthorityConfiguration?.Subject?.CommonName ?? c.Arn!.split("/").pop()!,
    href: `/pca/ca?arn=${encodeURIComponent(c.Arn!)}`,
    detail: `${c.Type?.toLowerCase()} · ${c.Status?.toLowerCase().replace(/_/g, " ")}`,
    signal: c.Status === "PENDING_CERTIFICATE" ? { tone: "warn" as const, text: "Needs a certificate" } : c.Status === "EXPIRED" ? { tone: "bad" as const, text: "Expired" } : undefined,
  }));
}
