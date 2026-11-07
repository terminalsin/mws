import "server-only";

import { ListCertificatesCommand } from "@aws-sdk/client-acm";
import { ListCertificateAuthoritiesCommand } from "@aws-sdk/client-acm-pca";
import { DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { DescribeLoadBalancersCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { ListAcceleratorsCommand } from "@aws-sdk/client-global-accelerator";
import { ListHostedZonesCommand } from "@aws-sdk/client-route-53";
import { type InventoryItem, tagMap } from "@mws-dashboard/aws";

import { acm, daysUntil, ec2, elb, ga, nameTag, pca, route53 } from "./clients";

const base = "/networking";

export async function vpcs(): Promise<InventoryItem[]> {
  const out = await (await ec2()).send(new DescribeVpcsCommand({}));
  return (out.Vpcs ?? []).map((v) => ({
    service: "vpc",
    type: "VPC",
    id: v.VpcId!,
    name: nameTag(v) ?? v.VpcId!,
    href: `${base}/vpc/${v.VpcId}`,
    detail: v.CidrBlock,
    tags: tagMap(v.Tags),
  }));
}

export async function hostedZones(): Promise<InventoryItem[]> {
  const out = await (await route53()).send(new ListHostedZonesCommand({}));
  return (out.HostedZones ?? []).map((z) => ({
    service: "route53",
    type: "Hosted zone",
    id: z.Id!,
    name: z.Name!.replace(/\.$/, ""),
    href: `${base}/route53/zone?id=${encodeURIComponent(z.Id!.split("/").pop()!)}`,
    detail: z.Config?.PrivateZone ? "Private" : "Public",
  }));
}

export async function loadBalancers(): Promise<InventoryItem[]> {
  const out = await (await elb()).send(new DescribeLoadBalancersCommand({}));
  return (out.LoadBalancers ?? []).map((l) => ({
    service: "elb",
    type: "Load balancer",
    id: l.LoadBalancerArn!,
    name: l.LoadBalancerName!,
    href: `${base}/elb/lb?arn=${encodeURIComponent(l.LoadBalancerArn!)}`,
    detail: l.DNSName,
    signal: l.State?.Code === "failed" ? { tone: "bad" as const, text: "Failed" } : undefined,
  }));
}

export async function accelerators(): Promise<InventoryItem[]> {
  const out = await (await ga()).send(new ListAcceleratorsCommand({}));
  return (out.Accelerators ?? []).map((a) => ({
    service: "globalaccelerator",
    type: "Accelerator",
    id: a.AcceleratorArn!,
    name: a.Name!,
    href: `${base}/ga/accelerator?arn=${encodeURIComponent(a.AcceleratorArn!)}`,
    detail: a.DnsName,
  }));
}

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
      href: `${base}/acm/cert?arn=${encodeURIComponent(c.CertificateArn!)}`,
      detail: c.Status?.toLowerCase().replace(/_/g, " "),
      signal,
    };
  });
}

export async function authorities(): Promise<InventoryItem[]> {
  const out = await (await pca()).send(new ListCertificateAuthoritiesCommand({}));
  return (out.CertificateAuthorities ?? []).map((c) => ({
    service: "acmpca",
    type: "Certificate authority",
    id: c.Arn!,
    name: c.CertificateAuthorityConfiguration?.Subject?.CommonName ?? c.Arn!.split("/").pop()!,
    href: `${base}/pca/ca?arn=${encodeURIComponent(c.Arn!)}`,
    detail: `${c.Type?.toLowerCase()} · ${c.Status?.toLowerCase().replace(/_/g, " ")}`,
    signal: c.Status === "PENDING_CERTIFICATE" ? { tone: "warn" as const, text: "Needs a certificate" } : c.Status === "EXPIRED" ? { tone: "bad" as const, text: "Expired" } : undefined,
  }));
}
