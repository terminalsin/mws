"use server";

import { DeleteCertificateCommand, ImportCertificateCommand, RenewCertificateCommand, RequestCertificateCommand } from "@aws-sdk/client-acm";
import { FieldError, act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { listItems } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { acm } from "../../lib/clients";

const certHref = (arn: string) => `/acm/cert?arn=${encodeURIComponent(arn)}`;

export async function requestCertificate(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const names = [...new Set(listItems(required(form, "domains", "Domain names")))];
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
  }, { fields: REQUEST_FIELDS });
}

const REQUEST_FIELDS = {
  DomainName: "domains",
  SubjectAlternativeNames: "domains",
  LimitExceededException: "domains",
  InvalidDomainValidationOptionsException: "domains",
  CertificateAuthorityArn: "pca",
  InvalidArnException: "pca",
  ResourceNotFoundException: "pca",
  KeyAlgorithm: "key",
  ValidationMethod: "validation",
};

// ImportCertificate answers every problem as a ValidationException; its
// message says which of the three PEM fields it is about.
const IMPORT_FIELDS: [RegExp, string, string][] = [
  [/private key is encrypted/i, "key", "Encrypted; decrypt it first (openssl pkey -in key.pem)"],
  [/does not match the certificate/i, "key", "Doesn't belong to this certificate"],
  [/parse key|private key/i, "key", "Not a readable private key"],
  [/more than one certificate/i, "certificate", "One certificate only; the others belong in the chain"],
  [/has expired/i, "certificate", "Expired"],
  [/not yet valid/i, "certificate", "Not valid yet"],
  [/parse certificate/i, "certificate", "Not a readable certificate"],
];

function importIssue(e: unknown, chain: boolean): unknown {
  if (!(e instanceof Error) || e.name !== "ValidationException") return e;
  const hit = IMPORT_FIELDS.find(([re]) => re.test(e.message));
  if (hit) return new FieldError(hit[1], hit[2]);
  if (/certificate chain/i.test(e.message)) return new FieldError(chain ? "chain" : "certificate", chain ? "Doesn't chain to this certificate" : "No certificate found");
  return e;
}

export async function importCertificate(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    const chain = text(form, "chain");
    const out = await (await acm())
      .send(
        new ImportCertificateCommand({
          Certificate: enc(required(form, "certificate", "Certificate body")),
          PrivateKey: enc(required(form, "key", "Private key")),
          CertificateChain: chain ? enc(chain) : undefined,
        }),
      )
      .catch((e: unknown) => {
        throw importIssue(e, !!chain);
      });
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
