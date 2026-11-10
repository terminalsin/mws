import { DescribeCertificateAuthorityCommand, GetCertificateAuthorityCertificateCommand, ListCertificateAuthoritiesCommand, ListTagsCommand } from "@aws-sdk/client-acm-pca";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Field, Page, Section, Sheet, Specs, Status, Tags } from "@mws-dashboard/ui";
import { BadgeCheck, CalendarClock, FileSignature, KeyRound, Pause, Play, RotateCcw, ShieldCheck, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, pca } from "../../../lib/clients";
import { CA_TONE } from "../../../lib/pca";
import { activateRoot, deleteAuthority, issueFromCsr, restoreAuthority, setAuthorityStatus, signSubordinate } from "../actions";

export const metadata: Metadata = { title: "Certificate authority" };

type Props = { searchParams: Promise<{ arn?: string }> };

export default async function Authority({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/pca", label: "Private CAs" };
  const data = await load(async () => {
    const client = await pca();
    const [ca, cert, tags, all] = await Promise.all([
      client.send(new DescribeCertificateAuthorityCommand({ CertificateAuthorityArn: arn })).then((r) => r.CertificateAuthority!),
      client.send(new GetCertificateAuthorityCertificateCommand({ CertificateAuthorityArn: arn })).then((r) => r, () => undefined),
      client.send(new ListTagsCommand({ CertificateAuthorityArn: arn })).then((r) => r.Tags, () => undefined),
      client.send(new ListCertificateAuthoritiesCommand({})).then((r) => r.CertificateAuthorities ?? []),
    ]);
    return { ca, cert, tags, all };
  });
  if (!data.ok) {
    return (
      <Page title="Certificate authority" icon={ICONS.ca} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { ca, cert, tags, all } = data.value;
  const cfg = ca.CertificateAuthorityConfiguration;
  const subject = cfg?.Subject;
  const name = subject?.CommonName ?? arn.split("/").pop();
  const parents = all.filter((c) => c.Status === "ACTIVE" && c.Arn !== arn);
  const pending = ca.Status === "PENDING_CERTIFICATE";
  const crl = ca.RevocationConfiguration?.CrlConfiguration;
  const ocsp = ca.RevocationConfiguration?.OcspConfiguration;
  return (
    <Page
      title={name}
      icon={ICONS.ca}
      back={back}
      subtitle={arn}
      actions={
        <>
          {pending && ca.Type === "ROOT" && (
            <Sheet title="Install CA certificate" label="Install CA certificate" icon={<BadgeCheck size={16} />} testId="install-ca-cert">
              <ActionForm action={activateRoot.bind(null, arn)} submit="Confirm and install" testId="install-ca-cert">
                <div className="form-row">
                  <Field label="Validity (years)">
                    <input name="years" type="number" min={1} max={30} defaultValue={10} />
                  </Field>
                  <Field label="Signature algorithm">
                    <select name="signing" defaultValue={cfg?.SigningAlgorithm}>
                      {["SHA256WITHRSA", "SHA384WITHRSA", "SHA512WITHRSA", "SHA256WITHECDSA", "SHA384WITHECDSA", "SHA512WITHECDSA"].map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </Field>
                </div>
              </ActionForm>
            </Sheet>
          )}
          {pending &&
            ca.Type === "SUBORDINATE" &&
            parents.map((p) => (
              <ActionForm
                key={p.Arn}
                action={signSubordinate.bind(null, p.Arn!, arn)}
                submit={`Sign with ${p.CertificateAuthorityConfiguration?.Subject?.CommonName}`}
                icon={<FileSignature size={16} />}
              />
            ))}
          {ca.Status === "ACTIVE" && (
            <Sheet title="Issue certificate" label="Issue certificate" icon={<FileSignature size={16} />} testId="issue-certificate">
              <ActionForm action={issueFromCsr.bind(null, arn)} submit="Issue" testId="issue-certificate">
                <textarea name="csr" rows={8} required aria-label="CSR" placeholder="-----BEGIN CERTIFICATE REQUEST-----" className="code-editor" />
                <Field label="Validity (days)">
                  <input name="days" type="number" min={1} defaultValue={365} />
                </Field>
                <input type="hidden" name="signing" value={cfg?.SigningAlgorithm} />
              </ActionForm>
            </Sheet>
          )}
          {ca.Status === "ACTIVE" && <ActionForm action={setAuthorityStatus.bind(null, arn, "DISABLED")} submit="Disable CA" icon={<Pause size={16} />} />}
          {ca.Status === "DISABLED" && <ActionForm action={setAuthorityStatus.bind(null, arn, "ACTIVE")} submit="Enable CA" icon={<Play size={16} />} />}
          {ca.Status === "DELETED" ? (
            <ActionForm action={restoreAuthority.bind(null, arn)} submit="Restore CA" icon={<RotateCcw size={16} />} />
          ) : (
            ca.Status !== "ACTIVE" && <ActionForm action={deleteAuthority.bind(null, arn)} submit="Delete CA" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${name}? It can be restored for 7 days.`} testId="delete-ca" />
          )}
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <ShieldCheck size={15} />, value: <Status tone={CA_TONE[ca.Status ?? ""] ?? "neutral"}>{ca.Status?.toLowerCase().replace(/_/g, " ")}</Status> },
          { label: "Type", icon: <AwsIcon icon={ICONS.ca} size={16} />, value: ca.Type === "ROOT" ? "Root" : "Subordinate" },
          { label: "Key algorithm", icon: <KeyRound size={15} />, value: cfg?.KeyAlgorithm?.replace(/_/g, " ") },
          ca.NotAfter && { label: "Expires", icon: <CalendarClock size={15} />, value: when(ca.NotAfter) },
          ca.Status === "DELETED" && ca.RestorableUntil && { label: "Restorable until", icon: <RotateCcw size={15} />, value: when(ca.RestorableUntil) },
        ]}
      />
      {pending && <div className="banner">{ca.Type === "ROOT" ? "Install the CA certificate to start issuing." : "Sign this CA with a parent CA to start issuing."}</div>}
      <Section title="Subject">
        <dl className="facts">
          {Object.entries(subject ?? {})
            .filter(([, v]) => v)
            .map(([k, v]) => (
              <div key={k}>
                <dt>{k.replace(/([a-z])([A-Z])/g, "$1 $2")}</dt>
                <dd>{String(v)}</dd>
              </div>
            ))}
        </dl>
      </Section>
      {(crl?.Enabled || ocsp?.Enabled) && (
        <Section title="Revocation">
          <dl className="facts">
            {crl?.Enabled && (
              <div>
                <dt>CRL</dt>
                <dd>
                  s3://{crl.S3BucketName} · {crl.ExpirationInDays}d
                </dd>
              </div>
            )}
            {ocsp?.Enabled && (
              <div>
                <dt>OCSP</dt>
                <dd>{ocsp.OcspCustomCname ?? "Enabled"}</dd>
              </div>
            )}
          </dl>
        </Section>
      )}
      {cert?.Certificate && (
        <details>
          <summary>CA certificate</summary>
          <CodeBlock value={[cert.Certificate, cert.CertificateChain].filter(Boolean).join("\n")} label="CA certificate" />
        </details>
      )}
      <Tags tags={tags} />
    </Page>
  );
}
