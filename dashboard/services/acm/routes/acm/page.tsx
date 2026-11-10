import { ListCertificateAuthoritiesCommand } from "@aws-sdk/client-acm-pca";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { ImportCertificate, RequestCertificate } from "@mws-dashboard/ui/model/acm";
import { Upload } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, daysUntil, pca } from "../../lib/clients";
import { CERT_TONE, listCertificates, statusText } from "../../lib/acm";
import { importCertificate, requestCertificate } from "./actions";

export const metadata: Metadata = { title: "Certificate Manager" };

// The names go out as DomainName plus SubjectAlternativeNames, each held to
// the model's domain pattern; ACM's default quota is 10 names a certificate.
const DOMAINS: Rule = {
  ...RequestCertificate.SubjectAlternativeNames,
  maxLength: 10,
  item: { ...RequestCertificate.DomainName, required: false, format: "dnsName" },
};
const PEM = {
  certificate: { ...ImportCertificate.Certificate, format: "certificate" },
  key: { ...ImportCertificate.PrivateKey, format: "privateKey" },
  chain: { ...ImportCertificate.CertificateChain, format: "certificates" },
} satisfies Record<string, Rule>;

export default async function Certificates() {
  const [certs, cas] = await Promise.all([
    load(listCertificates),
    load(async () => ((await (await pca()).send(new ListCertificateAuthoritiesCommand({}))).CertificateAuthorities ?? []).filter((c) => c.Status === "ACTIVE")),
  ]);
  const request = (
    <Sheet title="Request certificate" label="Request certificate" testId="request-certificate">
      <ActionForm action={requestCertificate} submit="Request" testId="request-certificate">
        <Field label="Domain names" rule={DOMAINS}>
          <textarea name="domains" rows={2} required placeholder={"example.com\n*.example.com"} autoFocus />
        </Field>
        <div className="form-row">
          <Field label="Issuer" member="CertificateAuthorityArn">
            <select name="pca" defaultValue="">
              <option value="">Amazon (public)</option>
              {cas.ok &&
                cas.value.map((c) => (
                  <option key={c.Arn} value={c.Arn}>
                    Private · {c.CertificateAuthorityConfiguration?.Subject?.CommonName ?? c.Arn?.split("/").pop()}
                  </option>
                ))}
            </select>
          </Field>
          <Field label="Validation" member="ValidationMethod">
            <select name="validation" defaultValue="DNS">
              <option value="DNS">DNS</option>
              <option value="EMAIL">Email</option>
            </select>
          </Field>
          <Field label="Key" member="KeyAlgorithm">
            <select name="key" defaultValue="RSA_2048">
              <option value="RSA_2048">RSA 2048</option>
              <option value="EC_prime256v1">ECDSA P-256</option>
              <option value="EC_secp384r1">ECDSA P-384</option>
            </select>
          </Field>
        </div>
      </ActionForm>
    </Sheet>
  );
  const importSheet = (
    <Sheet title="Import certificate" label="Import certificate" icon={<Upload size={16} />} testId="import-certificate">
      <ActionForm action={importCertificate} submit="Import" testId="import-certificate">
        <Field label="Certificate body" rule={PEM.certificate}>
          <textarea name="certificate" rows={5} required placeholder="-----BEGIN CERTIFICATE-----" className="code-editor" spellCheck={false} />
        </Field>
        <Field label="Private key" rule={PEM.key}>
          <textarea name="key" rows={5} required placeholder="-----BEGIN PRIVATE KEY-----" className="code-editor" spellCheck={false} />
        </Field>
        <Field label="Certificate chain" rule={PEM.chain}>
          <textarea name="chain" rows={3} placeholder="-----BEGIN CERTIFICATE-----" className="code-editor" spellCheck={false} />
        </Field>
      </ActionForm>
    </Sheet>
  );
  const actions = (
    <>
      {importSheet}
      {request}
    </>
  );
  if (!certs.ok) {
    return (
      <Page title="Certificates" actions={actions}>
        <ErrorNotice error={certs.error} />
      </Page>
    );
  }
  const all = certs.value.sort((a, b) => (a.NotAfter?.getTime() ?? Infinity) - (b.NotAfter?.getTime() ?? Infinity));
  const soon = (c: (typeof all)[number]) => c.Status === "ISSUED" && (daysUntil(c.NotAfter) ?? 999) <= 30;
  return (
    <Page title="Certificates" actions={actions}>
      <Curated
        label="Certificates"
        sections={[
          { id: "attention", title: "Needs attention", items: all.filter((c) => soon(c) || CERT_TONE[c.Status ?? ""] === "bad" || c.Status === "PENDING_VALIDATION") },
          { id: "use", title: "In use", items: all.filter((c) => !soon(c) && c.Status === "ISSUED" && c.InUse) },
          { id: "idle", title: "Not in use", items: all.filter((c) => !soon(c) && c.Status !== "PENDING_VALIDATION" && CERT_TONE[c.Status ?? ""] !== "bad" && !(c.Status === "ISSUED" && c.InUse)) },
        ]}
        empty={<Empty icon={ICONS.acm} action={request} />}
        row={(c) => {
          const days = daysUntil(c.NotAfter);
          const extra = (c.SubjectAlternativeNameSummaries?.length ?? 1) - 1;
          return {
            key: c.CertificateArn!,
            icon: <AwsIcon icon={c.Type === "PRIVATE" ? ICONS.ca : ICONS.acm} size={24} />,
            title: c.DomainName,
            subtitle: extra > 0 ? `+${extra} more: ${c.SubjectAlternativeNameSummaries!.filter((n) => n !== c.DomainName).slice(0, 3).join(", ")}` : undefined,
            href: `/acm/cert?arn=${encodeURIComponent(c.CertificateArn!)}`,
            meta: (
              <>
                {c.Type && c.Type !== "AMAZON_ISSUED" && <Pill>{c.Type === "IMPORTED" ? "Imported" : "Private"}</Pill>}
                {c.RenewalEligibility === "ELIGIBLE" && c.Type === "AMAZON_ISSUED" && days !== undefined && <span title="Expires">{days >= 0 ? `${days}d left` : "expired"}</span>}
                {c.Type !== "AMAZON_ISSUED" && days !== undefined && <span title="Expires">{days >= 0 ? `${days}d left` : "expired"}</span>}
                <Status tone={days !== undefined && days <= 30 && c.Status === "ISSUED" ? "warn" : (CERT_TONE[c.Status ?? ""] ?? "neutral")}>{statusText(c.Status)}</Status>
              </>
            ),
          };
        }}
      />
    </Page>
  );
}
