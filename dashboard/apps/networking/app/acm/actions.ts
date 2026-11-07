"use server";

import { DeleteCertificateCommand, ImportCertificateCommand, RenewCertificateCommand, RequestCertificateCommand } from "@aws-sdk/client-acm";
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { acm } from "../../lib/clients";

const certHref = (arn: string) => `/acm/cert?arn=${encodeURIComponent(arn)}`;

export async function requestCertificate(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const names = required(form, "domains", "Domain names")
      .split(/[\s,]+/)
      .filter(Boolean);
    const pca = text(form, "pca");
    const out = await (await acm()).send(
      new RequestCertificateCommand({
        DomainName: names[0],
        SubjectAlternativeNames: names.length > 1 ? names : undefined,
        ValidationMethod: pca ? undefined : ((text(form, "validation") || "DNS") as "DNS" | "EMAIL"),
        CertificateAuthorityArn: pca || undefined,
        KeyAlgorithm: (text(form, "key") || undefined) as "RSA_2048" | undefined,
      }),
    );
    redirect(certHref(out.CertificateArn!));
  });
}

export async function importCertificate(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    const chain = text(form, "chain");
    const out = await (await acm()).send(
      new ImportCertificateCommand({
        Certificate: enc(required(form, "certificate", "Certificate body")),
        PrivateKey: enc(required(form, "key", "Private key")),
        CertificateChain: chain ? enc(chain) : undefined,
      }),
    );
    redirect(certHref(out.CertificateArn!));
  });
}

export async function deleteCertificate(arn: string) {
  return act(async () => {
    await (await acm()).send(new DeleteCertificateCommand({ CertificateArn: arn }));
    redirect("/acm");
  });
}

export async function renewCertificate(arn: string) {
  return act(async () => {
    await (await acm()).send(new RenewCertificateCommand({ CertificateArn: arn }));
    return "Renewal started";
  }, "/acm/cert");
}
