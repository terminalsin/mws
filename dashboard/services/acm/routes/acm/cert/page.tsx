import { DescribeCertificateCommand, GetCertificateCommand, ListTagsForCertificateCommand } from "@aws-sdk/client-acm";
import { ago, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags, type Rule } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { ExportCertificate, ImportCertificate } from "@mws-dashboard/ui/model/acm";
import { Ban, CalendarClock, Download, Eye, EyeOff, KeyRound, Link2, Mail, RefreshCw, ShieldCheck, Tag, Trash2, Upload } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, acm, daysUntil } from "../../../lib/clients";
import { CERT_TONE, statusText } from "../../../lib/acm";
import { createValidationRecords, deleteCertificate, exportCertificate, importCertificate, renewCertificate, resendEmail, revokeCertificate, saveTags, setTransparency } from "../actions";

export const metadata: Metadata = { title: "Certificate" };

type Props = { searchParams: Promise<{ arn?: string; tab?: string }> };

const PASSPHRASE: Rule = { ...ExportCertificate.Passphrase, type: "string", generate: "password" };
const PEM = {
  certificate: { ...ImportCertificate.Certificate, format: "certificate" },
  key: { ...ImportCertificate.PrivateKey, format: "privateKey" },
  chain: { ...ImportCertificate.CertificateChain, format: "certificates" },
} satisfies Record<string, Rule>;
const REASONS = ["UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED", "SUPERSEDED", "CESSATION_OF_OPERATION", "PRIVILEGE_WITHDRAWN"];

function usedBy(arn: string) {
  const [, , service, , , resource] = arn.split(":");
  const icon = service === "elasticloadbalancing" ? ICONS.alb : service === "cloudfront" ? "service/AmazonCloudFront" : service === "apigateway" ? "service/AmazonAPIGateway" : ICONS.acm;
  const name = resource?.split("/").slice(-2, -1)[0] ?? resource ?? arn;
  const href = service === "elasticloadbalancing" && resource?.startsWith("loadbalancer/") ? `/elb/lb?arn=${encodeURIComponent(arn)}` : undefined;
  return { icon, name, href };
}

export default async function Certificate({ searchParams }: Props) {
  const { arn = "", tab = "details" } = await searchParams;
  const back = { href: "/acm", label: "Certificates" };
  const data = await load(async () => {
    const client = await acm();
    const [d, pem, tags] = await Promise.all([
      client.send(new DescribeCertificateCommand({ CertificateArn: arn })).then((r) => r.Certificate!),
      client.send(new GetCertificateCommand({ CertificateArn: arn })).then((r) => r, () => undefined),
      client.send(new ListTagsForCertificateCommand({ CertificateArn: arn })).then((r) => r.Tags ?? [], () => []),
    ]);
    return { d, pem, tags };
  });
  if (!data.ok) {
    return (
      <Page title="Certificate" icon={ICONS.acm} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { d, pem, tags } = data.value;
  const days = daysUntil(d.NotAfter);
  const self = `/acm/cert?arn=${encodeURIComponent(arn)}`;
  const pending = d.Status === "PENDING_VALIDATION";
  const renewing = d.RenewalSummary?.RenewalStatus === "PENDING_VALIDATION" || d.RenewalSummary?.RenewalStatus === "PENDING_AUTO_RENEWAL";
  const options = [...(d.DomainValidationOptions ?? []), ...(d.RenewalSummary?.DomainValidationOptions ?? [])];
  const dnsPending = options.some((v) => v.ResourceRecord && v.ValidationStatus !== "SUCCESS");
  const exportable = d.Type === "PRIVATE" || d.Options?.Export === "ENABLED";
  const inUse = (d.InUseBy?.length ?? 0) > 0;
  const tabs = [
    { id: "details", label: "Details" },
    { id: "domains", label: "Domains", count: d.DomainValidationOptions?.length || d.SubjectAlternativeNames?.length },
    { id: "body", label: "Certificate" },
    { id: "tags", label: "Tags", count: tags.length || undefined },
  ];
  const active = tabs.some((t) => t.id === tab) ? tab : "details";

  let body: React.ReactNode = null;
  if (active === "details") {
    body = (
      <>
        <Facts
          items={[
            d.Subject && ["Subject", d.Subject],
            d.Serial && ["Serial", <code key="s">{d.Serial}</code>],
            d.NotBefore && ["Valid from", when(d.NotBefore)],
            d.CreatedAt && ["Requested", when(d.CreatedAt)],
            d.IssuedAt && ["Issued", when(d.IssuedAt)],
            d.ImportedAt && ["Imported", when(d.ImportedAt)],
            d.RevokedAt && ["Revoked", <span key="r" className="tone-bad">{when(d.RevokedAt)} · {statusText(d.RevocationReason)}</span>],
            d.SignatureAlgorithm && ["Signature algorithm", d.SignatureAlgorithm],
            d.KeyUsages?.length && ["Key usage", d.KeyUsages.map((k) => k.Name?.replace(/_/g, " ").toLowerCase()).join(", ")],
            d.ExtendedKeyUsages?.length && ["Extended key usage", d.ExtendedKeyUsages.map((k) => k.Name?.replace(/_/g, " ").toLowerCase()).join(", ")],
            d.Options?.CertificateTransparencyLoggingPreference && [
              "Transparency logging",
              d.Type === "AMAZON_ISSUED" ? (
                <ActionForm
                  key="ct"
                  action={setTransparency.bind(null, arn, d.Options.CertificateTransparencyLoggingPreference !== "ENABLED")}
                  submit={d.Options.CertificateTransparencyLoggingPreference === "ENABLED" ? "Turn transparency logging off" : "Turn transparency logging on"}
                  icon={d.Options.CertificateTransparencyLoggingPreference === "ENABLED" ? <Eye size={15} /> : <EyeOff size={15} />}
                  tone={d.Options.CertificateTransparencyLoggingPreference === "ENABLED" ? "primary" : "plain"}
                />
              ) : (
                statusText(d.Options.CertificateTransparencyLoggingPreference)
              ),
            ],
            d.Options?.Export && ["Export", statusText(d.Options.Export)],
            d.RenewalEligibility && ["Renewal eligibility", statusText(d.RenewalEligibility)],
            d.RenewalSummary && ["Renewal", `${statusText(d.RenewalSummary.RenewalStatus)}${d.RenewalSummary.RenewalStatusReason ? ` · ${statusText(d.RenewalSummary.RenewalStatusReason)}` : ""}${d.RenewalSummary.UpdatedAt ? ` · ${ago(d.RenewalSummary.UpdatedAt)}` : ""}`],
          ]}
        />
        {inUse && (
          <Section title="In use by" count={d.InUseBy!.length} plain>
            <List
              label="In use by"
              rows={d.InUseBy!.map((a) => {
                const u = usedBy(a);
                return { key: a, icon: <AwsIcon icon={u.icon} size={22} />, title: u.name, href: u.href };
              })}
            />
          </Section>
        )}
      </>
    );
  } else if (active === "domains") {
    const validations = d.DomainValidationOptions ?? [];
    body =
      validations.length > 0 ? (
        <Section
          title="Domains"
          count={validations.length}
          plain
          actions={dnsPending && <ActionForm action={createValidationRecords.bind(null, arn, undefined)} submit="Create records in Route 53" icon={<AwsIcon icon="service/AmazonRoute53" size={16} />} testId="create-records" />}
        >
          <List
            label="Domains"
            rows={options.map((v, i) => ({
              key: `${v.DomainName}-${i}`,
              icon: <ShieldCheck size={18} className={v.ValidationStatus === "SUCCESS" ? "tone-good" : "tone-warn"} />,
              title: v.DomainName,
              subtitle: v.ResourceRecord ? (
                <code className="clip">
                  {v.ResourceRecord.Name} {v.ResourceRecord.Type} {v.ResourceRecord.Value}
                </code>
              ) : (
                v.ValidationEmails?.join(", ")
              ),
              meta: <Status tone={v.ValidationStatus === "SUCCESS" ? "good" : v.ValidationStatus === "FAILED" ? "bad" : "warn"}>{statusText(v.ValidationStatus)}</Status>,
              actions:
                v.ValidationStatus === "SUCCESS" ? undefined : v.ValidationMethod === "EMAIL" || (!v.ResourceRecord && v.ValidationEmails?.length) ? (
                  <ActionForm action={resendEmail.bind(null, arn, v.DomainName!, v.ValidationDomain ?? v.DomainName!)} submit={`Resend validation email for ${v.DomainName}`} icon={<Mail size={15} />} />
                ) : v.ResourceRecord ? (
                  <ActionForm action={createValidationRecords.bind(null, arn, v.DomainName!)} submit={`Create record in Route 53 for ${v.DomainName}`} icon={<AwsIcon icon="service/AmazonRoute53" size={15} />} />
                ) : undefined,
            }))}
          />
        </Section>
      ) : (
        <Section title="Names">
          <div className="chips">
            {(d.SubjectAlternativeNames ?? [d.DomainName!]).map((n) => (
              <Pill key={n}>{n}</Pill>
            ))}
          </div>
        </Section>
      );
  } else if (active === "body") {
    body = pem ? (
      <>
        <Section
          title="Certificate body"
          actions={
            <a className="icon-button plain" download={`${d.DomainName}.pem`} href={`data:application/x-pem-file;base64,${Buffer.from([pem.Certificate, pem.CertificateChain].filter(Boolean).join("\n")).toString("base64")}`} aria-label="Download certificate and chain" title="Download">
              <Download size={16} />
            </a>
          }
        >
          <CodeBlock value={pem.Certificate} label="Certificate body" />
        </Section>
        {pem.CertificateChain && (
          <Section title="Certificate chain">
            <CodeBlock value={pem.CertificateChain} label="Certificate chain" />
          </Section>
        )}
      </>
    ) : (
      <Empty>Not issued yet</Empty>
    );
  } else {
    body = (
      <Section
        title="Tags"
        actions={
          <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
            <ActionForm action={saveTags.bind(null, arn, tags.map((t) => t.Key!))} submit="Save" testId="edit-tags">
              <Field label="Tags" format="tags">
                <textarea name="tags" rows={6} defaultValue={tags.map((t) => `${t.Key}=${t.Value ?? ""}`).join("\n")} />
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {tags.length ? <Tags tags={tags} /> : <Empty>No tags</Empty>}
      </Section>
    );
  }

  return (
    <Page
      title={d.DomainName}
      icon={d.Type === "PRIVATE" ? ICONS.ca : ICONS.acm}
      back={back}
      subtitle={arn}
      actions={
        <>
          {d.RenewalEligibility === "ELIGIBLE" && d.Type === "PRIVATE" && <ActionForm action={renewCertificate.bind(null, arn)} submit="Renew" icon={<RefreshCw size={16} />} testId="renew-certificate" />}
          {exportable && d.Status === "ISSUED" && (
            <Sheet title="Export certificate" label="Export" icon={<Download size={16} />} testId="export-certificate">
              <ActionForm action={exportCertificate.bind(null, arn)} submit="Export" testId="export-certificate">
                <Field label="Passphrase" rule={PASSPHRASE} member="Passphrase">
                  <input name="passphrase" type="password" required autoComplete="new-password" />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {d.Type === "IMPORTED" && (
            <Sheet title="Reimport certificate" label="Reimport" icon={<Upload size={16} />} testId="reimport-certificate">
              <ActionForm action={importCertificate.bind(null, arn)} submit="Reimport" testId="reimport-certificate">
                <Field label="Certificate body" rule={PEM.certificate}>
                  <textarea name="certificate" rows={5} required className="code-editor" spellCheck={false} />
                </Field>
                <Field label="Private key" rule={PEM.key}>
                  <textarea name="key" rows={5} required className="code-editor" spellCheck={false} />
                </Field>
                <Field label="Certificate chain" rule={PEM.chain}>
                  <textarea name="chain" rows={3} className="code-editor" spellCheck={false} />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {d.Options?.Export === "ENABLED" && d.Status === "ISSUED" && (
            <Sheet title="Revoke certificate" label="Revoke" icon={<Ban size={16} />} testId="revoke-certificate">
              <ActionForm action={revokeCertificate.bind(null, arn)} submit="Revoke" tone="danger" testId="revoke-certificate">
                <Field label="Reason">
                  <select name="reason" defaultValue="UNSPECIFIED">
                    {REASONS.map((r) => (
                      <option key={r} value={r}>
                        {statusText(r)}
                      </option>
                    ))}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {inUse ? (
            <button type="button" className="icon-button plain" disabled aria-label="In use; can't be deleted" title="In use; can't be deleted">
              <Trash2 size={16} />
            </button>
          ) : (
            <ActionForm action={deleteCertificate.bind(null, arn)} submit="Delete certificate" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${d.DomainName}?`} testId="delete-certificate" />
          )}
        </>
      }
    >
      {(pending || renewing) && <LiveRefresh />}
      <Specs
        items={[
          { label: "Status", icon: <ShieldCheck size={15} />, value: <Status tone={CERT_TONE[d.Status ?? ""] ?? "neutral"}>{statusText(d.Status)}</Status> },
          d.NotAfter && { label: "Expires", icon: <CalendarClock size={15} />, value: <span className={days !== undefined && days <= 30 ? "tone-warn" : undefined}>{when(d.NotAfter)}{days !== undefined && days >= 0 ? ` · ${days}d` : ""}</span> },
          { label: "Key algorithm", icon: <KeyRound size={15} />, value: d.KeyAlgorithm?.replace(/_/g, " ").replace("EC prime256v1", "ECDSA P-256") },
          d.Issuer && {
            label: "Issuer",
            icon: <AwsIcon icon={d.Type === "PRIVATE" ? ICONS.ca : ICONS.acm} size={16} />,
            value: d.CertificateAuthorityArn ? <Link href={`/pca/ca?arn=${encodeURIComponent(d.CertificateAuthorityArn)}`}>{d.Issuer}</Link> : d.Issuer,
          },
          d.Type && d.Type !== "AMAZON_ISSUED" && { label: "Type", icon: <Link2 size={15} />, value: d.Type === "IMPORTED" ? "Imported" : "Private" },
          d.RenewalSummary && { label: "Renewal", icon: <RefreshCw size={15} />, value: statusText(d.RenewalSummary.RenewalStatus) },
        ]}
      />
      {d.FailureReason && <div className="banner error">{statusText(d.FailureReason)}</div>}
      {pending && dnsPending && active !== "domains" && (
        <div className="banner">
          Waiting for DNS validation. <Link href={`${self}&tab=domains`}>Domains</Link>
          <ActionForm action={createValidationRecords.bind(null, arn, undefined)} submit="Create records in Route 53" icon={<AwsIcon icon="service/AmazonRoute53" size={16} />} testId="create-records" />
        </div>
      )}
      <Segments label="Certificate" items={tabs.map((t) => ({ label: t.label, href: t.id === "details" ? self : `${self}&tab=${t.id}`, active: t.id === active, count: t.count }))} />
      {body}
    </Page>
  );
}
