"use server";

import {
  CreateCertificateAuthorityCommand,
  DeleteCertificateAuthorityCommand,
  GetCertificateAuthorityCsrCommand,
  GetCertificateCommand,
  ImportCertificateAuthorityCertificateCommand,
  IssueCertificateCommand,
  RestoreCertificateAuthorityCommand,
  UpdateCertificateAuthorityCommand,
  type KeyAlgorithm,
  type SigningAlgorithm,
} from "@aws-sdk/client-acm-pca";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { pca } from "../../lib/clients";

const caHref = (arn: string) => `/pca/ca?arn=${encodeURIComponent(arn)}`;
const SIGNING: Record<string, SigningAlgorithm> = { RSA_2048: "SHA256WITHRSA", RSA_4096: "SHA512WITHRSA", EC_prime256v1: "SHA256WITHECDSA", EC_secp384r1: "SHA384WITHECDSA" };

async function issued(CertificateAuthorityArn: string, CertificateArn: string) {
  const client = await pca();
  for (let i = 0; ; i++) {
    try {
      return await client.send(new GetCertificateCommand({ CertificateAuthorityArn, CertificateArn }));
    } catch (e) {
      if (i >= 20 || (e as Error).name !== "RequestInProgressException") throw e;
      await new Promise((r) => setTimeout(r, 250));
    }
  }
}

export async function createAuthority(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const key = (text(form, "key") || "RSA_2048") as KeyAlgorithm;
    const out = await (await pca()).send(
      new CreateCertificateAuthorityCommand({
        CertificateAuthorityType: (text(form, "type") || "ROOT") as "ROOT" | "SUBORDINATE",
        UsageMode: (text(form, "usage") || "GENERAL_PURPOSE") as "GENERAL_PURPOSE" | "SHORT_LIVED_CERTIFICATE",
        CertificateAuthorityConfiguration: {
          KeyAlgorithm: key,
          SigningAlgorithm: SIGNING[key] ?? "SHA256WITHRSA",
          Subject: {
            CommonName: required(form, "cn", "Common name"),
            Organization: text(form, "org") || undefined,
            Country: text(form, "country") || undefined,
          },
        },
        IdempotencyToken: `console${Date.now()}`.slice(0, 36),
      }),
    );
    redirect(caHref(out.CertificateAuthorityArn!));
  });
}

/** Install a root CA's own certificate: sign its CSR with itself, as the
 * console's "Install CA certificate" does for a root. */
export async function activateRoot(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await pca();
    const csr = (await client.send(new GetCertificateAuthorityCsrCommand({ CertificateAuthorityArn: arn }))).Csr!;
    const years = Number(text(form, "years") || 10);
    const { CertificateArn } = await client.send(
      new IssueCertificateCommand({
        CertificateAuthorityArn: arn,
        Csr: new TextEncoder().encode(csr),
        SigningAlgorithm: (text(form, "signing") || "SHA256WITHRSA") as SigningAlgorithm,
        TemplateArn: "arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity: { Type: "YEARS", Value: years },
      }),
    );
    const cert = await issued(arn, CertificateArn!);
    await client.send(new ImportCertificateAuthorityCertificateCommand({ CertificateAuthorityArn: arn, Certificate: new TextEncoder().encode(cert.Certificate!) }));
    return "CA certificate installed";
  }, "/pca", "/pca/ca");
}

export async function signSubordinate(parent: string, child: string) {
  return act(async () => {
    const client = await pca();
    const csr = (await client.send(new GetCertificateAuthorityCsrCommand({ CertificateAuthorityArn: child }))).Csr!;
    const { CertificateArn } = await client.send(
      new IssueCertificateCommand({
        CertificateAuthorityArn: parent,
        Csr: new TextEncoder().encode(csr),
        SigningAlgorithm: "SHA256WITHRSA",
        TemplateArn: "arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen0/V1",
        Validity: { Type: "YEARS", Value: 5 },
      }),
    );
    const cert = await issued(parent, CertificateArn!);
    await client.send(
      new ImportCertificateAuthorityCertificateCommand({
        CertificateAuthorityArn: child,
        Certificate: new TextEncoder().encode(cert.Certificate!),
        CertificateChain: new TextEncoder().encode(cert.CertificateChain ?? ""),
      }),
    );
    return "Subordinate CA certificate installed";
  }, "/pca", "/pca/ca");
}

export async function setAuthorityStatus(arn: string, status: "ACTIVE" | "DISABLED") {
  return act(async () => {
    await (await pca()).send(new UpdateCertificateAuthorityCommand({ CertificateAuthorityArn: arn, Status: status }));
    return status === "ACTIVE" ? "Enabled" : "Disabled";
  }, "/pca", "/pca/ca");
}

export async function deleteAuthority(arn: string) {
  return act(async () => {
    await (await pca()).send(new DeleteCertificateAuthorityCommand({ CertificateAuthorityArn: arn, PermanentDeletionTimeInDays: 7 }));
    return "Deletion scheduled";
  }, "/pca", "/pca/ca");
}

export async function restoreAuthority(arn: string) {
  return act(async () => {
    await (await pca()).send(new RestoreCertificateAuthorityCommand({ CertificateAuthorityArn: arn }));
    return "Restored";
  }, "/pca", "/pca/ca");
}

export async function issueFromCsr(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await pca();
    const { CertificateArn } = await client.send(
      new IssueCertificateCommand({
        CertificateAuthorityArn: arn,
        Csr: new TextEncoder().encode(required(form, "csr", "CSR")),
        SigningAlgorithm: (text(form, "signing") || "SHA256WITHRSA") as SigningAlgorithm,
        Validity: { Type: "DAYS", Value: Number(text(form, "days") || 365) },
      }),
    );
    const cert = await issued(arn, CertificateArn!);
    return { ok: true, message: "Issued", detail: cert.Certificate };
  });
}
