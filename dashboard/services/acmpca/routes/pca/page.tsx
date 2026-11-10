import { ListCertificateAuthoritiesCommand } from "@aws-sdk/client-acm-pca";
import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ICONS, pca } from "../../lib/clients";
import { CA_TONE } from "../../lib/pca";
import { createAuthority } from "./actions";

export const metadata: Metadata = { title: "Private CA" };

export default async function Authorities() {
  const cas = await load(async () => (await (await pca()).send(new ListCertificateAuthoritiesCommand({}))).CertificateAuthorities ?? []);
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
        <Field label="Common name">
          <input name="cn" required autoFocus placeholder="Example Root CA" />
        </Field>
        <div className="form-row">
          <Field label="Organization">
            <input name="org" />
          </Field>
          <Field label="Country">
            <input name="country" maxLength={2} placeholder="US" />
          </Field>
        </div>
        <Field label="Key algorithm">
          <select name="key" defaultValue="RSA_2048">
            <option value="RSA_2048">RSA 2048</option>
            <option value="RSA_4096">RSA 4096</option>
            <option value="EC_prime256v1">ECDSA P-256</option>
            <option value="EC_secp384r1">ECDSA P-384</option>
          </select>
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
    <Page title="Private certificate authorities" actions={create}>
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
