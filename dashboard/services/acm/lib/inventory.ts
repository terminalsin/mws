import "server-only";

import { ListCertificatesCommand } from "@aws-sdk/client-acm";
import { type InventoryItem } from "@mws-dashboard/aws";

import { acm, daysUntil } from "./clients";

export async function certificates(): Promise<InventoryItem[]> {
  const out = await (await acm()).send(new ListCertificatesCommand({ Includes: { keyTypes: ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"] } }));
  return (out.CertificateSummaryList ?? []).map((c) => {
    const days = daysUntil(c.NotAfter);
    const signal =
      c.Status === "EXPIRED" || (days !== undefined && days < 0)
        ? { tone: "bad" as const, text: "Expired" }
        : days !== undefined && days <= 30
          ? { tone: "warn" as const, text: `Expires in ${days}d` }
          : c.Status === "FAILED"
            ? { tone: "bad" as const, text: "Validation failed" }
            : undefined;
    return {
      service: "acm",
      type: "Certificate",
      id: c.CertificateArn!,
      name: c.DomainName!,
      href: `/acm/cert?arn=${encodeURIComponent(c.CertificateArn!)}`,
      detail: c.Status?.toLowerCase().replace(/_/g, " "),
      signal,
    };
  });
}
