"use client";

// The request form opens on its issuers: Amazon's public CA and each active
// private CA as a tile. Picking one shows only what that issuer needs; key,
// validation method, export and tags wait under More.

import { FieldShell } from "@mws-dashboard/ui/fields";
import { RequestCertificate } from "@mws-dashboard/ui/model/acm";
import { MoreFields, PresetGallery, type PresetItem } from "@mws-dashboard/ui/presets";
import type { Rule } from "@mws-dashboard/ui";
import { useState } from "react";

// The names go out as DomainName plus SubjectAlternativeNames, each held to
// the model's domain pattern; ACM's default quota is 10 names a certificate.
const DOMAINS: Rule = {
  ...RequestCertificate.SubjectAlternativeNames,
  maxLength: 10,
  item: { ...RequestCertificate.DomainName, required: false, format: "dnsName" },
};

export interface Issuer {
  /** "" for Amazon's public CA, else the private CA's ARN. */
  arn: string;
  name: string;
}

export function RequestFields({ issuers }: { issuers: Issuer[] }) {
  const items: (PresetItem & { arn: string })[] = [
    { id: "public", arn: "", label: "Public", icon: "service/AWSCertificateManager", title: "Amazon public certificate" },
    ...issuers.map((i) => ({ id: i.arn, arn: i.arn, label: i.name, icon: "resource/AWSCertificateManagerCertificateAuthority", group: "Private CA", title: i.arn })),
  ];
  const [issuer, setIssuer] = useState(items[0]);
  const isPublic = !issuer.arn;
  return (
    <>
      {items.length > 1 && <PresetGallery presets={items} chosen={issuer.id} choose={setIssuer} label="Issuer" testId="issuer" />}
      <input type="hidden" name="pca" value={issuer.arn} />
      <div key={issuer.id} className="preset-fields">
        <FieldShell label="Domain names" rule={DOMAINS}>
          <textarea name="domains" rows={2} required placeholder={isPublic ? "example.com\n*.example.com" : "api.internal.example"} autoFocus />
        </FieldShell>
        <MoreFields>
          <div className="form-row">
            <FieldShell label="Key" member="KeyAlgorithm">
              <select name="key" defaultValue="RSA_2048">
                <option value="RSA_2048">RSA 2048</option>
                <option value="EC_prime256v1">ECDSA P-256</option>
                <option value="EC_secp384r1">ECDSA P-384</option>
              </select>
            </FieldShell>
            {isPublic && (
              <FieldShell label="Validation" member="ValidationMethod">
                <select name="validation" defaultValue="DNS">
                  <option value="DNS">DNS</option>
                  <option value="EMAIL">Email</option>
                </select>
              </FieldShell>
            )}
            <FieldShell label="Transparency logging" member="Options.CertificateTransparencyLoggingPreference">
              <select name="ct" defaultValue="on">
                <option value="on">Enabled</option>
                <option value="off">Disabled</option>
              </select>
            </FieldShell>
          </div>
          {isPublic && (
            <label className="check">
              <input type="checkbox" name="export" /> Allow export
            </label>
          )}
          <FieldShell label="Tags" format="tags">
            <textarea name="tags" rows={2} placeholder="team=web" />
          </FieldShell>
        </MoreFields>
      </div>
    </>
  );
}
