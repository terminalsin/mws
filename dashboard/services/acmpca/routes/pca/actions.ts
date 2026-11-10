"use server";

import {
  CreateCertificateAuthorityAuditReportCommand,
  CreateCertificateAuthorityCommand,
  CreatePermissionCommand,
  DeleteCertificateAuthorityCommand,
  DeletePermissionCommand,
  DeletePolicyCommand,
  DescribeCertificateAuthorityCommand,
  GetCertificateAuthorityCsrCommand,
  GetCertificateCommand,
  ImportCertificateAuthorityCertificateCommand,
  IssueCertificateCommand,
  PutPolicyCommand,
  RestoreCertificateAuthorityCommand,
  RevokeCertificateCommand,
  TagCertificateAuthorityCommand,
  UntagCertificateAuthorityCommand,
  UpdateCertificateAuthorityCommand,
  type ActionType,
  type AuditReportResponseFormat,
  type KeyAlgorithm,
  type KeyStorageSecurityStandard,
  type RevocationConfiguration,
  type RevocationReason,
  type SigningAlgorithm,
} from "@aws-sdk/client-acm-pca";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { pca } from "../../lib/clients";
import { DAY, DEFAULT_SIGNING } from "../../lib/pca";

const caHref = (arn: string) => `/pca/ca?arn=${encodeURIComponent(arn)}`;
const enc = (s: string) => new TextEncoder().encode(s);

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

function tagLines(form: FormData) {
  return text(form, "tags")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i) => {
      const [Key, ...rest] = l.split("=");
      if (!rest.length || !Key.trim()) throw new FieldError("tags", `Line ${i + 1}: key=value`, "format");
      return { Key: Key.trim(), Value: rest.join("=").trim() };
    });
}

/** CRL and OCSP settings from a form (`crl`, `crlBucket`, `crlDays`, `ocsp`). */
function revocation(form: FormData): RevocationConfiguration {
  const crl = text(form, "crl") === "on";
  const ocsp = text(form, "ocsp") === "on";
  if (crl && !text(form, "crlBucket")) throw new FieldError("crlBucket", "A CRL needs an S3 bucket", "required");
  return {
    CrlConfiguration: crl
      ? {
          Enabled: true,
          S3BucketName: text(form, "crlBucket"),
          ExpirationInDays: Number(text(form, "crlDays") || 7),
          CustomCname: text(form, "crlCname") || undefined,
          S3ObjectAcl: "BUCKET_OWNER_FULL_CONTROL",
        }
      : { Enabled: false },
    OcspConfiguration: ocsp ? { Enabled: true, OcspCustomCname: text(form, "ocspCname") || undefined } : { Enabled: false },
  };
}

const REVOCATION_FIELDS = {
  "RevocationConfiguration.CrlConfiguration.S3BucketName": "crlBucket",
  "RevocationConfiguration.CrlConfiguration.ExpirationInDays": "crlDays",
  "RevocationConfiguration.CrlConfiguration.CustomCname": "crlCname",
  "RevocationConfiguration.OcspConfiguration.OcspCustomCname": "ocspCname",
  InvalidArgsException: "crlBucket",
  InsufficientPermissionsException: "crlBucket",
};

export async function createAuthority(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const key = (text(form, "key") || "RSA_2048") as KeyAlgorithm;
    const Tags = tagLines(form);
    const out = await (await pca()).send(
      new CreateCertificateAuthorityCommand({
        CertificateAuthorityType: (text(form, "type") || "ROOT") as "ROOT" | "SUBORDINATE",
        UsageMode: (text(form, "usage") || "GENERAL_PURPOSE") as "GENERAL_PURPOSE" | "SHORT_LIVED_CERTIFICATE",
        CertificateAuthorityConfiguration: {
          KeyAlgorithm: key,
          SigningAlgorithm: (DEFAULT_SIGNING[key] ?? "SHA256WITHRSA") as SigningAlgorithm,
          Subject: {
            CommonName: required(form, "cn", "Common name"),
            Organization: text(form, "org") || undefined,
            OrganizationalUnit: text(form, "ou") || undefined,
            Country: text(form, "country") || undefined,
            State: text(form, "state") || undefined,
            Locality: text(form, "locality") || undefined,
          },
        },
        RevocationConfiguration: revocation(form),
        KeyStorageSecurityStandard: (text(form, "storage") || undefined) as KeyStorageSecurityStandard | undefined,
        Tags: Tags.length ? Tags : undefined,
        IdempotencyToken: `console${Date.now()}`.slice(0, 36),
      }),
    );
    redirect(caHref(out.CertificateAuthorityArn!));
  }, { fields: { ...REVOCATION_FIELDS, Tags: "tags", InvalidTagException: "tags", KeyAlgorithm: "key", KeyStorageSecurityStandard: "storage" } });
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
        Csr: enc(csr),
        SigningAlgorithm: (text(form, "signing") || "SHA256WITHRSA") as SigningAlgorithm,
        TemplateArn: "arn:aws:acm-pca:::template/RootCACertificate/V1",
        Validity: { Type: "YEARS", Value: years },
      }),
    );
    const cert = await issued(arn, CertificateArn!);
    await client.send(new ImportCertificateAuthorityCertificateCommand({ CertificateAuthorityArn: arn, Certificate: enc(cert.Certificate!) }));
    return "CA certificate installed";
  }, { revalidate: ["/pca", "/pca/ca"], fields: { ValidationException: "years" } });
}

/** Sign a pending subordinate with a parent CA in this account: the parent
 * signs with its own key's algorithm, with a path length below its own and a
 * validity that ends before the parent's. */
export async function signSubordinate(child: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await pca();
    const parent = required(form, "parent", "Parent CA");
    const p = (await client.send(new DescribeCertificateAuthorityCommand({ CertificateAuthorityArn: parent }))).CertificateAuthority!;
    if (p.Status !== "ACTIVE") throw new FieldError("parent", "The parent CA must be active");
    if (p.UsageMode === "SHORT_LIVED_CERTIFICATE") throw new FieldError("parent", "A short-lived certificate CA can't sign CA certificates");
    const left = p.NotAfter ? Math.floor((p.NotAfter.getTime() - Date.now()) / DAY) - 1 : 3650;
    const days = Number(text(form, "days") || Math.min(1825, left));
    if (days > left) throw new FieldError("days", `The parent expires in ${left + 1} days`, "range", { min: 1, max: left });
    const pathLen = text(form, "pathLen") || "0";
    const key = p.CertificateAuthorityConfiguration?.KeyAlgorithm ?? "RSA_2048";
    const csr = (await client.send(new GetCertificateAuthorityCsrCommand({ CertificateAuthorityArn: child }))).Csr!;
    const { CertificateArn } = await client.send(
      new IssueCertificateCommand({
        CertificateAuthorityArn: parent,
        Csr: enc(csr),
        SigningAlgorithm: (p.CertificateAuthorityConfiguration?.SigningAlgorithm ?? DEFAULT_SIGNING[key] ?? "SHA256WITHRSA") as SigningAlgorithm,
        TemplateArn: `arn:aws:acm-pca:::template/SubordinateCACertificate_PathLen${pathLen}/V1`,
        Validity: { Type: "DAYS", Value: days },
      }),
    );
    const cert = await issued(parent, CertificateArn!);
    await client.send(
      new ImportCertificateAuthorityCertificateCommand({
        CertificateAuthorityArn: child,
        Certificate: enc(cert.Certificate!),
        CertificateChain: enc(cert.CertificateChain ?? ""),
      }),
    );
    return "Subordinate CA certificate installed";
  }, { revalidate: ["/pca", "/pca/ca"], fields: { ValidationException: "days", MalformedCSRException: "parent", InvalidStateException: "parent" } });
}

/** Install a CA certificate signed elsewhere (an external or other-account parent). */
export async function importCaCertificate(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const chain = text(form, "chain");
    await (await pca()).send(
      new ImportCertificateAuthorityCertificateCommand({ CertificateAuthorityArn: arn, Certificate: enc(required(form, "certificate", "Certificate")), CertificateChain: chain ? enc(chain) : undefined }),
    );
    return "CA certificate installed";
  }, { revalidate: ["/pca", "/pca/ca"], fields: { Certificate: "certificate", CertificateChain: "chain", MalformedCertificateException: "certificate", CertificateMismatchException: "certificate", InvalidRequestException: "chain" } });
}

export async function setAuthorityStatus(arn: string, status: "ACTIVE" | "DISABLED") {
  return act(async () => {
    await (await pca()).send(new UpdateCertificateAuthorityCommand({ CertificateAuthorityArn: arn, Status: status }));
    return status === "ACTIVE" ? "Enabled" : "Disabled";
  }, "/pca", "/pca/ca");
}

export async function saveRevocation(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await pca()).send(new UpdateCertificateAuthorityCommand({ CertificateAuthorityArn: arn, RevocationConfiguration: revocation(form) }));
    return "Revocation configuration saved";
  }, { revalidate: ["/pca/ca"], fields: REVOCATION_FIELDS });
}

export async function deleteAuthority(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const days = Number(text(form, "days") || 30);
    await (await pca()).send(new DeleteCertificateAuthorityCommand({ CertificateAuthorityArn: arn, PermanentDeletionTimeInDays: days }));
    return `Deletion scheduled; restorable for ${days} days`;
  }, { revalidate: ["/pca", "/pca/ca"], fields: { PermanentDeletionTimeInDays: "days" } });
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
    const template = text(form, "template");
    const notBefore = text(form, "notBefore");
    const { CertificateArn } = await client.send(
      new IssueCertificateCommand({
        CertificateAuthorityArn: arn,
        Csr: enc(required(form, "csr", "CSR")),
        SigningAlgorithm: (text(form, "signing") || "SHA256WITHRSA") as SigningAlgorithm,
        TemplateArn: template ? `arn:aws:acm-pca:::template/${template}` : undefined,
        Validity: { Type: "DAYS", Value: Number(text(form, "days") || 365) },
        ValidityNotBefore: notBefore ? { Type: "ABSOLUTE", Value: Math.floor(new Date(notBefore).getTime() / 1000) } : undefined,
      }),
    );
    const cert = await issued(arn, CertificateArn!);
    const serial = new (await import("node:crypto")).X509Certificate(cert.Certificate!).serialNumber;
    return { ok: true, message: `Issued serial ${serial}`, detail: [`${CertificateArn}`, cert.Certificate, cert.CertificateChain].filter(Boolean).join("\n") };
    // The only plain ValidationException here is a validity past the CA's.
  }, { fields: { MalformedCSRException: "csr", ValidationException: "days", InvalidArgsException: "template" } });
}

export async function revokeCertificate(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const serial = required(form, "serial", "Serial").replace(/[\s:]/g, "").toLowerCase();
    // AWS takes the serial as colon-separated hex pairs.
    const CertificateSerial = (serial.length % 2 ? `0${serial}` : serial).match(/../g)!.join(":");
    await (await pca()).send(new RevokeCertificateCommand({ CertificateAuthorityArn: arn, CertificateSerial, RevocationReason: (text(form, "reason") || "UNSPECIFIED") as RevocationReason }));
    return `Revoked ${CertificateSerial}`;
  }, { fields: { CertificateSerial: "serial", ResourceNotFoundException: "serial", RequestAlreadyProcessedException: "serial", InvalidRequestException: "serial", RevocationReason: "reason" } });
}

/** Let ACM renew private certificates this CA issued (AWS's "Authorize ACM access to renew"). */
export async function grantAcm(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const Actions = form.getAll("actions").map(String) as ActionType[];
    if (!Actions.length) throw new FieldError("actions", "Choose at least one action", "required");
    await (await pca()).send(new CreatePermissionCommand({ CertificateAuthorityArn: arn, Principal: "acm.amazonaws.com", Actions }));
    return "ACM may now renew this CA's certificates";
  }, { revalidate: ["/pca/ca"], fields: { Actions: "actions", PermissionAlreadyExistsException: "actions" } });
}

export async function revokePermission(arn: string, principal: string, account: string | undefined) {
  return act(async () => {
    await (await pca()).send(new DeletePermissionCommand({ CertificateAuthorityArn: arn, Principal: principal, SourceAccount: account }));
    return "Permission removed";
  }, "/pca/ca");
}

export async function savePolicy(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await pca()).send(new PutPolicyCommand({ ResourceArn: arn, Policy: required(form, "policy", "Policy") }));
    return "Policy saved";
  }, { revalidate: ["/pca/ca"], fields: { Policy: "policy", InvalidPolicyException: "policy", LockoutPreventedException: "policy" } });
}

export async function deletePolicy(arn: string) {
  return act(async () => {
    await (await pca()).send(new DeletePolicyCommand({ ResourceArn: arn }));
    return "Policy deleted";
  }, "/pca/ca");
}

export async function auditReport(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const bucket = required(form, "bucket", "Bucket");
    const out = await (await pca()).send(
      new CreateCertificateAuthorityAuditReportCommand({ CertificateAuthorityArn: arn, S3BucketName: bucket, AuditReportResponseFormat: (text(form, "format") || "JSON") as AuditReportResponseFormat }),
    );
    redirect(`${caHref(arn)}&tab=audit&report=${out.AuditReportId}&key=${encodeURIComponent(out.S3Key ?? "")}&bucket=${encodeURIComponent(bucket)}`);
  }, { fields: { S3BucketName: "bucket", InvalidArgsException: "bucket", RequestFailedException: "bucket" } });
}

export async function saveTags(arn: string, before: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const c = await pca();
    const Tags = tagLines(form);
    const gone = before.filter((k) => !Tags.some((t) => t.Key === k));
    if (gone.length) await c.send(new UntagCertificateAuthorityCommand({ CertificateAuthorityArn: arn, Tags: gone.map((Key) => ({ Key })) }));
    if (Tags.length) await c.send(new TagCertificateAuthorityCommand({ CertificateAuthorityArn: arn, Tags }));
    return "Tags saved";
  }, { revalidate: ["/pca/ca"], fields: { Tags: "tags", InvalidTagException: "tags", TooManyTagsException: "tags" } });
}
