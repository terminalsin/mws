import "server-only";

import { ListConnectorsCommand } from "@aws-sdk/client-pca-connector-scep";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { listAuthorities } from "./cas";
import { scep } from "./clients";

export async function authorities(): Promise<InventoryItem[]> {
  return (await listAuthorities()).map((c) => ({
    service: "acmpca",
    type: "Certificate authority",
    id: c.Arn!,
    name: c.CertificateAuthorityConfiguration?.Subject?.CommonName ?? c.Arn!.split("/").pop()!,
    href: `/pca/ca?arn=${encodeURIComponent(c.Arn!)}`,
    detail: `${c.Type?.toLowerCase()} · ${c.Status?.toLowerCase().replace(/_/g, " ")}`,
    signal: c.Status === "PENDING_CERTIFICATE" ? { tone: "warn" as const, text: "Needs a certificate" } : c.Status === "EXPIRED" ? { tone: "bad" as const, text: "Expired" } : c.Status === "FAILED" ? { tone: "bad" as const, text: c.FailureReason ?? "Failed" } : undefined,
  }));
}

export async function connectors(): Promise<InventoryItem[]> {
  const c = await scep();
  const list = await all((NextToken) => c.send(new ListConnectorsCommand({ NextToken })), (r) => r.Connectors, (r) => r.NextToken);
  return list.map((k) => ({
    service: "acmpca",
    type: "SCEP connector",
    id: k.Arn!,
    name: k.Arn!.split("/").pop()!,
    href: `/pca/connector?arn=${encodeURIComponent(k.Arn!)}`,
    detail: k.Type === "INTUNE" ? "Intune" : "general purpose",
    signal: k.Status === "FAILED" ? { tone: "bad" as const, text: k.StatusReason ?? "Failed" } : undefined,
  }));
}
