import "server-only";

import { type InventoryItem } from "@mws-dashboard/aws";

import { listCertificates } from "./acm";
import { daysUntil } from "./clients";

export async function certificates(): Promise<InventoryItem[]> {
  return (await listCertificates()).map((c) => {
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
