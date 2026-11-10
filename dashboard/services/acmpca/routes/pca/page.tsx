import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreateCertificateAuthority } from "@mws-dashboard/ui/model/acm-pca";
import { Smartphone } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { listAuthorities } from "../../lib/cas";
import { ICONS } from "../../lib/clients";
import { CA_TONE, KEY_ALGORITHMS } from "../../lib/pca";
import { RevocationFields } from "./revocation";
import { createAuthority } from "./actions";

export const metadata: Metadata = { title: "Private CA" };

const SUBJECT = CreateCertificateAuthority.CertificateAuthorityConfiguration.fields!.Subject.fields!;
// The model allows any two letters; a real ISO code is what clients expect,
// so names ("Germany"), alpha-3 ("DEU") and withdrawn codes ("UK") repair.
const COUNTRY: Rule = { format: "country" };

export default async function Authorities() {
  const cas = await load(listAuthorities);
  const create = (
    <Sheet title="Create private CA" label="Create CA" testId="create-ca">
      <ActionForm action={createAuthority} submit="Create CA" testId="create-ca">
        <div className="form-row">
          <Field label="Mode">
            <select name="usage" defaultValue="GENERAL_PURPOSE">
              <option value="GENERAL_PURPOSE">General-purpose</option>
              <option value="SHORT_LIVED_CERTIFICATE">Short-lived certificate</option>
            </select>
          </Field>
          <Field label="Type">
            <select name="type" defaultValue="ROOT">
              <option value="ROOT">Root</option>
              <option value="SUBORDINATE">Subordinate</option>
            </select>
          </Field>
        </div>
        <Field label="Common name" rule={SUBJECT.CommonName} member="Subject.CommonName">
          <input name="cn" required autoFocus placeholder="Example Root CA" />
        </Field>
        <div className="form-row">
          <Field label="Organization" rule={SUBJECT.Organization} member="Subject.Organization">
            <input name="org" />
          </Field>
          <Field label="Organizational unit" rule={SUBJECT.OrganizationalUnit} member="Subject.OrganizationalUnit">
            <input name="ou" />
          </Field>
        </div>
        <div className="form-row">
          <Field label="Country" rule={COUNTRY} member="Subject.Country">
            <input name="country" placeholder="US" />
          </Field>
          <Field label="State" rule={SUBJECT.State} member="Subject.State">
            <input name="state" />
          </Field>
          <Field label="Locality" rule={SUBJECT.Locality} member="Subject.Locality">
            <input name="locality" />
          </Field>
        </div>
        <div className="form-row">
          <Field label="Key algorithm" member="KeyAlgorithm">
            <select name="key" defaultValue="RSA_2048">
              {KEY_ALGORITHMS.map((k) => (
                <option key={k} value={k}>
                  {k.replace(/_/g, " ").replace("EC prime256v1", "ECDSA P-256").replace("EC secp384r1", "ECDSA P-384").replace("EC secp521r1", "ECDSA P-521")}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Key storage" member="KeyStorageSecurityStandard">
            <select name="storage" defaultValue="">
              <option value="">FIPS 140-2 level 3 or higher</option>
              <option value="FIPS_140_2_LEVEL_2_OR_HIGHER">FIPS 140-2 level 2 or higher</option>
              <option value="CCPC_LEVEL_1_OR_HIGHER">CCPC level 1 or higher</option>
            </select>
          </Field>
        </div>
        <details>
          <summary>Revocation</summary>
          <RevocationFields />
        </details>
        <Field label="Tags" format="tags">
          <textarea name="tags" rows={2} placeholder="team=pki" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  if (!cas.ok) {
    return (
      <Page title="Private certificate authorities" actions={create}>
        <ErrorNotice error={cas.error} />
      </Page>
    );
  }
  const all = cas.value;
  return (
    <Page
      title="Private certificate authorities"
      actions={
        <>
          <Link className="icon-button plain" href="/pca/connectors" aria-label="Connectors for SCEP" title="Connectors for SCEP">
            <Smartphone size={16} />
          </Link>
          {create}
        </>
      }
    >
      <Curated
        label="Certificate authorities"
        sections={[
          { id: "root", title: "Root", items: all.filter((c) => c.Type === "ROOT") },
          { id: "sub", title: "Subordinate", items: all.filter((c) => c.Type !== "ROOT") },
        ]}
        empty={<Empty icon={ICONS.pca} action={create} />}
        row={(c) => ({
          key: c.Arn!,
          icon: <AwsIcon icon={ICONS.ca} size={24} />,
          title: c.CertificateAuthorityConfiguration?.Subject?.CommonName ?? c.Arn!.split("/").pop(),
          subtitle: c.CertificateAuthorityConfiguration?.Subject?.Organization,
          href: `/pca/ca?arn=${encodeURIComponent(c.Arn!)}`,
          meta: (
            <>
              {c.UsageMode === "SHORT_LIVED_CERTIFICATE" && <Pill>Short-lived</Pill>}
              <Pill>{c.Type === "ROOT" ? "Root" : "Subordinate"}</Pill>
              {c.NotAfter && <span title="Expires">{ago(c.NotAfter)}</span>}
              <Status tone={CA_TONE[c.Status ?? ""] ?? "neutral"}>{c.Status?.toLowerCase().replace(/_/g, " ")}</Status>
            </>
          ),
        })}
      />
    </Page>
  );
}
