"use server";

import {
  AddTagsToCertificateCommand,
  DeleteCertificateCommand,
  DescribeCertificateCommand,
  ExportCertificateCommand,
  ImportCertificateCommand,
  PutAccountConfigurationCommand,
  RemoveTagsFromCertificateCommand,
  RenewCertificateCommand,
  RequestCertificateCommand,
  ResendValidationEmailCommand,
  RevokeCertificateCommand,
  UpdateCertificateOptionsCommand,
  type RevocationReason,
} from "@aws-sdk/client-acm";
import { ChangeResourceRecordSetsCommand, ListHostedZonesCommand, Route53Client } from "@aws-sdk/client-route-53";
import { FieldError, act, all, client, required, text, type ActionResult } from "@mws-dashboard/aws";
import { listItems } from "@mws-dashboard/ui/validation";
import { redirect } from "next/navigation";

import { acm } from "../../lib/clients";

const certHref = (arn: string) => `/acm/cert?arn=${encodeURIComponent(arn)}`;
const enc = (s: string) => new TextEncoder().encode(s);

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

export async function requestCertificate(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const names = [...new Set(listItems(required(form, "domains", "Domain names")))];
    const pca = text(form, "pca");
    const Tags = tagLines(form);
    const out = await (await acm()).send(
      new RequestCertificateCommand({
        DomainName: names[0],
        SubjectAlternativeNames: names.length > 1 ? names : undefined,
        ValidationMethod: pca ? undefined : ((text(form, "validation") || "DNS") as "DNS" | "EMAIL"),
        CertificateAuthorityArn: pca || undefined,
        KeyAlgorithm: (text(form, "key") || undefined) as "RSA_2048" | undefined,
        Options: {
          CertificateTransparencyLoggingPreference: text(form, "ct") === "off" ? "DISABLED" : "ENABLED",
          ...(text(form, "export") === "on" && !pca ? { Export: "ENABLED" as const } : {}),
        },
        Tags: Tags.length ? Tags : undefined,
        IdempotencyToken: text(form, "token") || undefined,
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
  Tags: "tags",
  InvalidTagException: "tags",
  TooManyTagsException: "tags",
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

/** Import a certificate, or with `arn` reimport over an imported one (same
 * ARN, so whatever uses it picks up the new certificate). */
export async function importCertificate(arn: string | undefined, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const chain = text(form, "chain");
    const Tags = arn ? [] : tagLines(form);
    const out = await (await acm())
      .send(
        new ImportCertificateCommand({
          CertificateArn: arn,
          Certificate: enc(required(form, "certificate", "Certificate body")),
          PrivateKey: enc(required(form, "key", "Private key")),
          CertificateChain: chain ? enc(chain) : undefined,
          Tags: Tags.length ? Tags : undefined,
        }),
      )
      .catch((e: unknown) => {
        throw importIssue(e, !!chain);
      });
    if (arn) return "Certificate reimported";
    redirect(certHref(out.CertificateArn!));
  }, { revalidate: ["/acm/cert"], fields: { Tags: "tags", InvalidTagException: "tags" } });
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

/** The public hosted zone a name belongs to: the longest zone name it ends in. */
async function zoneFor(r53: Route53Client, name: string) {
  const zones = await all((Marker) => r53.send(new ListHostedZonesCommand({ Marker })), (r) => r.HostedZones, (r) => (r.IsTruncated ? r.NextMarker : undefined));
  const fqdn = name.replace(/\.?$/, ".").toLowerCase();
  return zones
    .filter((z) => !z.Config?.PrivateZone && (fqdn === z.Name!.toLowerCase() || fqdn.endsWith(`.${z.Name!.toLowerCase()}`)))
    .sort((a, b) => b.Name!.length - a.Name!.length)[0];
}

/** ACM's "Create records in Route 53": UPSERT each pending domain's
 * validation CNAME into the public hosted zone it belongs to. */
export async function createValidationRecords(arn: string, only?: string) {
  return act(async () => {
    const r53 = await client(Route53Client);
    const d = (await (await acm()).send(new DescribeCertificateCommand({ CertificateArn: arn }))).Certificate!;
    const pending = (d.DomainValidationOptions ?? []).filter((v) => v.ResourceRecord && v.ValidationStatus !== "SUCCESS" && (!only || v.DomainName === only));
    if (!pending.length) throw new Error("No domain is waiting for a DNS record");
    const byZone = new Map<string, { name: string; value: string }[]>();
    const missing: string[] = [];
    for (const v of pending) {
      const zone = await zoneFor(r53, v.DomainName!.replace(/^\*\./, ""));
      if (!zone) {
        missing.push(v.DomainName!);
        continue;
      }
      const list = byZone.get(zone.Id!) ?? [];
      // Wildcard and apex names share one record; write it once.
      if (!list.some((r) => r.name === v.ResourceRecord!.Name)) list.push({ name: v.ResourceRecord!.Name!, value: v.ResourceRecord!.Value! });
      byZone.set(zone.Id!, list);
    }
    for (const [HostedZoneId, records] of byZone) {
      await r53.send(
        new ChangeResourceRecordSetsCommand({
          HostedZoneId,
          ChangeBatch: {
            Comment: `ACM validation for ${d.DomainName}`,
            Changes: records.map((r) => ({ Action: "UPSERT", ResourceRecordSet: { Name: r.name, Type: "CNAME", TTL: 300, ResourceRecords: [{ Value: r.value }] } })),
          },
        }),
      );
    }
    const made = [...byZone.values()].reduce((n, r) => n + r.length, 0);
    if (missing.length && !made) throw new Error(`No public hosted zone in Route 53 for ${missing.join(", ")}`);
    return `${made} record${made === 1 ? "" : "s"} created${missing.length ? `; no hosted zone for ${missing.join(", ")}` : ""}`;
  }, "/acm/cert");
}

export async function resendEmail(arn: string, domain: string, validationDomain: string) {
  return act(async () => {
    await (await acm()).send(new ResendValidationEmailCommand({ CertificateArn: arn, Domain: domain, ValidationDomain: validationDomain }));
    return `Validation email resent for ${domain}`;
  }, "/acm/cert");
}

/** Export a private (or exportable public) certificate with its private key,
 * encrypted with the passphrase. */
export async function exportCertificate(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const passphrase = required(form, "passphrase", "Passphrase");
    if (passphrase.length < 4) throw new FieldError("passphrase", "At least 4 characters", "tooShort", { minLength: 4 });
    const out = await (await acm()).send(new ExportCertificateCommand({ CertificateArn: arn, Passphrase: enc(passphrase) }));
    return { ok: true, message: "Exported", detail: [out.Certificate, out.CertificateChain, out.PrivateKey].filter(Boolean).join("\n") };
  }, { fields: { Passphrase: "passphrase" } });
}

export async function setTransparency(arn: string, enabled: boolean) {
  return act(async () => {
    await (await acm()).send(new UpdateCertificateOptionsCommand({ CertificateArn: arn, Options: { CertificateTransparencyLoggingPreference: enabled ? "ENABLED" : "DISABLED" } }));
    return enabled ? "Transparency logging on" : "Transparency logging off";
  }, "/acm/cert");
}

export async function revokeCertificate(arn: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await acm()).send(new RevokeCertificateCommand({ CertificateArn: arn, RevocationReason: (text(form, "reason") || "UNSPECIFIED") as RevocationReason }));
    return "Revoked";
  }, { revalidate: ["/acm", "/acm/cert"], fields: { RevocationReason: "reason" } });
}

export async function saveTags(arn: string, before: string[], _: ActionResult | null, form: FormData) {
  return act(async () => {
    const c = await acm();
    const Tags = tagLines(form);
    const gone = before.filter((k) => !Tags.some((t) => t.Key === k));
    if (gone.length) await c.send(new RemoveTagsFromCertificateCommand({ CertificateArn: arn, Tags: gone.map((Key) => ({ Key })) }));
    if (Tags.length) await c.send(new AddTagsToCertificateCommand({ CertificateArn: arn, Tags }));
    return "Tags saved";
  }, { revalidate: ["/acm/cert"], fields: { Tags: "tags", InvalidTagException: "tags", TooManyTagsException: "tags", TagPolicyException: "tags" } });
}

export async function saveExpiryEvents(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const days = Number(required(form, "days", "Days"));
    await (await acm()).send(new PutAccountConfigurationCommand({ ExpiryEvents: { DaysBeforeExpiry: days }, IdempotencyToken: `console${Date.now()}`.slice(0, 32) }));
    return `Expiry events start ${days} days before`;
  }, { revalidate: ["/acm"], fields: { DaysBeforeExpiry: "days", ValidationException: "days" } });
}
