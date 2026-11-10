import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { GitBranch, Smartphone } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { listAuthorities } from "../../lib/cas";
import { ICONS } from "../../lib/clients";
import { CaFields } from "../../lib/ca-fields";
import { CA_TONE, caName } from "../../lib/pca";
import { RevocationFields } from "./revocation";
import { createAuthority } from "./actions";

export const metadata: Metadata = { title: "Private CA" };

export default async function Authorities() {
  const cas = await load(listAuthorities);
  const list = cas.ok ? cas.value : [];
  const create = (
    <Sheet title="Create private CA" label="Create CA" testId="create-ca">
      <ActionForm action={createAuthority} submit="Create CA" testId="create-ca">
        <CaFields names={list.map(caName)} hasRoot={list.some((c) => c.Type === "ROOT" && c.Status === "ACTIVE")}>
          <details>
            <summary>Revocation</summary>
            <RevocationFields />
          </details>
          <Field label="Tags" format="tags">
            <textarea name="tags" rows={2} placeholder="team=pki" />
          </Field>
        </CaFields>
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
          icon: c.Type === "ROOT" ? <AwsIcon icon={ICONS.ca} size={24} /> : <GitBranch size={22} aria-label="Subordinate" />,
          title: c.CertificateAuthorityConfiguration?.Subject?.CommonName ?? c.Arn!.split("/").pop(),
          subtitle: c.CertificateAuthorityConfiguration?.Subject?.Organization,
          href: `/pca/ca?arn=${encodeURIComponent(c.Arn!)}`,
          meta: (
            <>
              {c.UsageMode === "SHORT_LIVED_CERTIFICATE" && <Pill>Short-lived</Pill>}
              {c.CertificateAuthorityConfiguration?.KeyAlgorithm && !c.CertificateAuthorityConfiguration.KeyAlgorithm.startsWith("RSA") && <Pill>{c.CertificateAuthorityConfiguration.KeyAlgorithm.startsWith("EC_") ? "ECDSA" : c.CertificateAuthorityConfiguration.KeyAlgorithm.replace(/_/g, "-")}</Pill>}
              {c.NotAfter && c.Status === "ACTIVE" && <span title="Expires">{ago(c.NotAfter)}</span>}
              <Status tone={CA_TONE[c.Status ?? ""] ?? "neutral"}>{c.Status?.toLowerCase().replace(/_/g, " ")}</Status>
            </>
          ),
        })}
      />
    </Page>
  );
}
