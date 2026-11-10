import {
  DescribeCertificateAuthorityAuditReportCommand,
  DescribeCertificateAuthorityCommand,
  GetCertificateAuthorityCertificateCommand,
  GetCertificateAuthorityCsrCommand,
  GetPolicyCommand,
  ListPermissionsCommand,
  ListTagsCommand,
} from "@aws-sdk/client-acm-pca";
import { ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { all, client, load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, Empty, ErrorNotice, Facts, Field, List, Page, Pill, Section, Segments, Sheet, Specs, Status, Tags, type Rule } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { IssueCertificate, PutPolicy, RevokeCertificate } from "@mws-dashboard/ui/model/acm-pca";
import { Ban, BadgeCheck, CalendarClock, Download, FileSignature, KeyRound, Pause, Pencil, Play, RotateCcw, ShieldCheck, Tag, Trash2, Upload, UserCheck } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { listAuthorities } from "../../../lib/cas";
import { ICONS, pca } from "../../../lib/clients";
import { CA_TONE, DAY, TEMPLATES, caName, signingFor } from "../../../lib/pca";
import {
  activateRoot,
  auditReport,
  deleteAuthority,
  deletePolicy,
  grantAcm,
  importCaCertificate,
  issueFromCsr,
  restoreAuthority,
  revokeCertificate,
  revokePermission,
  saveRevocation,
  savePolicy,
  saveTags,
  setAuthorityStatus,
  signSubordinate,
} from "../actions";
import { RevocationFields } from "../revocation";

export const metadata: Metadata = { title: "Certificate authority" };

const CSR: Rule = { ...IssueCertificate.Csr, type: "string", format: "csr" };
const VALIDITY = IssueCertificate.Validity.fields!.Value;
const POLICY: Rule = { ...PutPolicy.Policy, format: "policy" };
const SERIAL: Rule = { ...RevokeCertificate.CertificateSerial, hint: "Hex, with or without colons" };
const REASONS = ["UNSPECIFIED", "KEY_COMPROMISE", "CERTIFICATE_AUTHORITY_COMPROMISE", "AFFILIATION_CHANGED", "SUPERSEDED", "CESSATION_OF_OPERATION", "PRIVILEGE_WITHDRAWN", "A_A_COMPROMISE"];
const PEM_CERT: Rule = { format: "certificate", required: true };
const PEM_CHAIN: Rule = { format: "certificates" };

type Props = { searchParams: Promise<{ arn?: string; tab?: string; report?: string; key?: string; bucket?: string }> };

const pretty = (s: string) => s.toLowerCase().replace(/_/g, " ");

export default async function Authority({ searchParams }: Props) {
  const { arn = "", tab = "details", report, key: reportKey, bucket: reportBucket } = await searchParams;
  const back = { href: "/pca", label: "Private CAs" };
  const data = await load(async () => {
    const c = await pca();
    const [ca, cert, tags] = await Promise.all([
      c.send(new DescribeCertificateAuthorityCommand({ CertificateAuthorityArn: arn })).then((r) => r.CertificateAuthority!),
      c.send(new GetCertificateAuthorityCertificateCommand({ CertificateAuthorityArn: arn })).then((r) => r, () => undefined),
      c.send(new ListTagsCommand({ CertificateAuthorityArn: arn })).then((r) => r.Tags ?? [], () => []),
    ]);
    return { ca, cert, tags };
  });
  if (!data.ok) {
    return (
      <Page title="Certificate authority" icon={ICONS.ca} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { ca, cert, tags } = data.value;
  const c = await pca();
  const cfg = ca.CertificateAuthorityConfiguration;
  const subject = cfg?.Subject;
  const name = subject?.CommonName ?? arn.split("/").pop();
  const pending = ca.Status === "PENDING_CERTIFICATE" || ca.Status === "CREATING";
  // A CA that is still CREATING gets its CSR in a moment; the actions wait for it.
  const self = `/pca/ca?arn=${encodeURIComponent(arn)}`;
  const crl = ca.RevocationConfiguration?.CrlConfiguration;
  const ocsp = ca.RevocationConfiguration?.OcspConfiguration;
  // A certificate may not outlive its CA (nor, in short-lived mode, 7 days):
  // say so in the field, where a clamp fixes it, not after a round trip.
  const caDays = ca.NotAfter ? Math.floor((ca.NotAfter.getTime() - Date.now()) / DAY) : undefined;
  const maxDays = ca.UsageMode === "SHORT_LIVED_CERTIFICATE" ? Math.min(7, caDays ?? 7) : caDays;
  const days: Rule = { ...VALIDITY, max: maxDays };
  const signing = signingFor(cfg?.KeyAlgorithm);
  // Parents that can sign this subordinate: active, general-purpose, not itself.
  const parents = pending && ca.Type === "SUBORDINATE" ? (await listAuthorities().catch(() => [])).filter((p) => p.Status === "ACTIVE" && p.Arn !== arn && p.UsageMode !== "SHORT_LIVED_CERTIFICATE") : [];
  const csr = pending ? await c.send(new GetCertificateAuthorityCsrCommand({ CertificateAuthorityArn: arn })).then((r) => r.Csr, () => undefined) : undefined;
  const buckets = async () =>
    (await client(S3Client, { forcePathStyle: true }))
      .send(new ListBucketsCommand({}))
      .then((r) => (r.Buckets ?? []).map((b) => b.Name!), () => [] as string[]);

  const tabs = [
    { id: "details", label: "Details" },
    { id: "certificate", label: pending ? "CA certificate (CSR)" : "CA certificate" },
    { id: "revocation", label: "Revocation configuration" },
    { id: "permissions", label: "Permissions" },
    { id: "policy", label: "Resource-based policy" },
    { id: "audit", label: "Audit reports" },
    { id: "tags", label: "Tags", count: tags.length || undefined },
  ];
  const active = tabs.some((t) => t.id === tab) ? tab : "details";

  let body: React.ReactNode = null;
  if (active === "details") {
    body = (
      <>
        <Facts
          items={[
            ca.FailureReason && ["Failure reason", <span key="f" className="tone-bad">{pretty(ca.FailureReason)}</span>],
            ca.Serial && ["Serial", <code key="s">{ca.Serial}</code>],
            cfg?.SigningAlgorithm && ["Signing algorithm", cfg.SigningAlgorithm],
            ["Mode", ca.UsageMode === "SHORT_LIVED_CERTIFICATE" ? "Short-lived certificate" : "General-purpose"],
            ca.NotBefore && ["Valid from", when(ca.NotBefore)],
            ca.NotAfter && ["Valid until", when(ca.NotAfter)],
            ca.CreatedAt && ["Created", when(ca.CreatedAt)],
            ca.LastStateChangeAt && ["Last state change", when(ca.LastStateChangeAt)],
            ca.OwnerAccount && ["Owner", ca.OwnerAccount],
            ca.KeyStorageSecurityStandard && ["Key storage", pretty(ca.KeyStorageSecurityStandard)],
          ]}
        />
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
      </>
    );
  } else if (active === "certificate") {
    body = pending ? (
      <Section
        title="Certificate signing request"
        actions={
          csr && (
            <a className="icon-button plain" download={`${name}.csr`} href={`data:application/pkcs10;base64,${Buffer.from(csr).toString("base64")}`} aria-label="Download CSR" title="Download CSR">
              <Download size={16} />
            </a>
          )
        }
      >
        {csr ? <CodeBlock value={csr} label="CSR" /> : <Empty>The CSR is being generated</Empty>}
      </Section>
    ) : cert?.Certificate ? (
      <>
        <Section
          title="CA certificate"
          actions={
            <a className="icon-button plain" download={`${name}.pem`} href={`data:application/x-pem-file;base64,${Buffer.from([cert.Certificate, cert.CertificateChain].filter(Boolean).join("\n")).toString("base64")}`} aria-label="Download CA certificate" title="Download">
              <Download size={16} />
            </a>
          }
        >
          <CodeBlock value={cert.Certificate} label="CA certificate" />
        </Section>
        {cert.CertificateChain && (
          <Section title="Certificate chain">
            <CodeBlock value={cert.CertificateChain} label="Certificate chain" />
          </Section>
        )}
      </>
    ) : (
      <Empty>No certificate</Empty>
    );
  } else if (active === "revocation") {
    body = (
      <Section
        title="Revocation configuration"
        actions={
          ca.Status !== "DELETED" && (
            <Sheet title="Revocation configuration" label="Edit revocation configuration" icon={<Pencil size={16} />} testId="edit-revocation">
              <ActionForm action={saveRevocation.bind(null, arn)} submit="Save" testId="edit-revocation">
                <RevocationFields buckets={await buckets()} d={{ crl: crl?.Enabled, bucket: crl?.S3BucketName, days: crl?.ExpirationInDays, crlCname: crl?.CustomCname, ocsp: ocsp?.Enabled, ocspCname: ocsp?.OcspCustomCname }} />
              </ActionForm>
            </Sheet>
          )
        }
      >
        <Facts
          items={[
            ["CRL", crl?.Enabled ? <Link key="c" href={`/s3/${encodeURIComponent(crl.S3BucketName!)}`}>s3://{crl.S3BucketName}</Link> : "Off"],
            crl?.Enabled && ["CRL valid", `${crl.ExpirationInDays} days`],
            crl?.CustomCname && ["CRL name", crl.CustomCname],
            ["OCSP", ocsp?.Enabled ? (ocsp.OcspCustomCname ?? "On") : "Off"],
          ]}
        />
      </Section>
    );
  } else if (active === "permissions") {
    const perms = await load(() => all((NextToken) => c.send(new ListPermissionsCommand({ CertificateAuthorityArn: arn, NextToken })), (r) => r.Permissions, (r) => r.NextToken));
    const acmGranted = perms.ok && perms.value.some((p) => p.Principal === "acm.amazonaws.com");
    body = (
      <Section
        title="Permissions"
        plain
        actions={
          !acmGranted && (
            <Sheet title="Authorize ACM" label="Authorize ACM to renew certificates" icon={<UserCheck size={16} />} testId="grant-acm">
              <ActionForm action={grantAcm.bind(null, arn)} submit="Authorize" testId="grant-acm">
                <fieldset className="checks">
                  <legend>acm.amazonaws.com may</legend>
                  {["IssueCertificate", "GetCertificate", "ListPermissions"].map((a) => (
                    <label key={a} className="check">
                      <input type="checkbox" name="actions" value={a} defaultChecked /> {a}
                    </label>
                  ))}
                </fieldset>
              </ActionForm>
            </Sheet>
          )
        }
      >
        {!perms.ok ? (
          <ErrorNotice error={perms.error} />
        ) : (
          <List
            label="Permissions"
            empty={<Empty>ACM can't renew this CA's private certificates until it is authorized</Empty>}
            rows={perms.value.map((p) => ({
              key: `${p.Principal}-${p.SourceAccount}`,
              icon: <AwsIcon icon="service/AWSCertificateManager" size={20} />,
              title: p.Principal,
              subtitle: [p.SourceAccount && `account ${p.SourceAccount}`, p.CreatedAt && when(p.CreatedAt)].filter(Boolean).join(" · "),
              meta: p.Actions?.map((a) => <Pill key={a}>{a}</Pill>),
              actions: <ActionForm action={revokePermission.bind(null, arn, p.Principal!, p.SourceAccount)} submit={`Remove permission for ${p.Principal}`} icon={<Trash2 size={15} />} tone="danger" confirm="Remove this permission?" />,
            }))}
          />
        )}
      </Section>
    );
  } else if (active === "policy") {
    const policy = await load(() => c.send(new GetPolicyCommand({ ResourceArn: arn })).then((r) => r.Policy, (e: Error) => (e.name === "ResourceNotFoundException" ? undefined : Promise.reject(e))));
    body = (
      <Section
        title="Resource-based policy"
        actions={
          policy.ok && (
            <>
              <Sheet title="Resource-based policy" label="Edit policy" icon={<Pencil size={16} />} testId="edit-policy">
                <ActionForm action={savePolicy.bind(null, arn)} submit="Save" testId="edit-policy">
                  <Field label="Policy" rule={POLICY}>
                    <textarea name="policy" rows={14} className="code-editor" spellCheck={false} defaultValue={policy.value ? JSON.stringify(JSON.parse(policy.value), null, 2) : template(arn)} />
                  </Field>
                </ActionForm>
              </Sheet>
              {policy.value && <ActionForm action={deletePolicy.bind(null, arn)} submit="Delete policy" icon={<Trash2 size={16} />} tone="danger" confirm="Delete the resource-based policy?" />}
            </>
          )
        }
      >
        {!policy.ok ? <ErrorNotice error={policy.error} /> : policy.value ? <CodeBlock value={policy.value} label="Policy" /> : <Empty>No policy; other accounts and RAM shares can't use this CA</Empty>}
      </Section>
    );
  } else if (active === "audit") {
    const status = report ? await load(() => c.send(new DescribeCertificateAuthorityAuditReportCommand({ CertificateAuthorityArn: arn, AuditReportId: report }))) : null;
    const list = await buckets();
    body = (
      <Section
        title="Audit report"
        actions={
          <Sheet title="Generate audit report" label="Generate audit report" icon={<FileSignature size={16} />} testId="audit-report">
            <ActionForm action={auditReport.bind(null, arn)} submit="Generate" testId="audit-report">
              <Field label="S3 bucket" format="bucket" known={list} member="S3BucketName">
                <input name="bucket" required />
              </Field>
              <Field label="Format">
                <select name="format" defaultValue="JSON">
                  <option>JSON</option>
                  <option>CSV</option>
                </select>
              </Field>
            </ActionForm>
          </Sheet>
        }
      >
        {status ? (
          status.ok ? (
            <>
              {status.value.AuditReportStatus === "CREATING" && <LiveRefresh />}
              <Facts
                items={[
                  ["Report", <code key="r">{report}</code>],
                  ["Status", <Status key="s" tone={status.value.AuditReportStatus === "SUCCESS" ? "good" : status.value.AuditReportStatus === "FAILED" ? "bad" : "info"}>{pretty(status.value.AuditReportStatus ?? "")}</Status>],
                  status.value.S3Key && reportBucket && ["Object", <Link key="o" href={`/s3/${encodeURIComponent(reportBucket)}?prefix=${encodeURIComponent(status.value.S3Key.slice(0, status.value.S3Key.lastIndexOf("/") + 1))}`}>s3://{reportBucket}/{status.value.S3Key}</Link>],
                  !status.value.S3Key && reportKey && reportBucket && ["Object", `s3://${reportBucket}/${reportKey}`],
                  status.value.CreatedAt && ["Created", when(status.value.CreatedAt)],
                ]}
              />
            </>
          ) : (
            <ErrorNotice error={status.error} />
          )
        ) : (
          <Empty>An audit report lists every certificate this CA issued or revoked</Empty>
        )}
      </Section>
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

  const parentMax = (p: (typeof parents)[number]) => (p.NotAfter ? Math.floor((p.NotAfter.getTime() - Date.now()) / DAY) - 1 : 3650);
  const longest = parents.length ? Math.max(...parents.map(parentMax)) : 1825;

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
                  <Field label="Validity (years)" rule={VALIDITY} member="Validity.Value">
                    <input name="years" type="number" max={30} defaultValue={10} />
                  </Field>
                  <Field label="Signature algorithm" member="SigningAlgorithm">
                    <select name="signing" defaultValue={cfg?.SigningAlgorithm}>
                      {signing.map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </Field>
                </div>
              </ActionForm>
            </Sheet>
          )}
          {pending && ca.Type === "SUBORDINATE" && parents.length > 0 && (
            <Sheet title="Install CA certificate" label="Sign with a private CA" icon={<BadgeCheck size={16} />} testId="sign-subordinate">
              <ActionForm action={signSubordinate.bind(null, arn)} submit="Sign and install" testId="sign-subordinate">
                <Field label="Parent CA">
                  <select name="parent" defaultValue={parents[0].Arn}>
                    {parents.map((p) => (
                      <option key={p.Arn} value={p.Arn}>
                        {caName(p)} · {p.CertificateAuthorityConfiguration?.KeyAlgorithm} · {p.Type === "ROOT" ? "root" : "subordinate"}
                      </option>
                    ))}
                  </select>
                </Field>
                <div className="form-row">
                  <Field label="Path length" hint="How many CAs may sit below this one">
                    <select name="pathLen" defaultValue="0">
                      {["0", "1", "2", "3"].map((n) => (
                        <option key={n}>{n}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Validity (days)" rule={{ ...VALIDITY, max: longest }} member="Validity.Value" hint="Ends before the parent">
                    <input name="days" type="number" defaultValue={Math.min(1825, longest)} />
                  </Field>
                </div>
              </ActionForm>
            </Sheet>
          )}
          {pending && (
            <Sheet title="Import CA certificate" label="Import a certificate signed elsewhere" icon={<Upload size={16} />} testId="import-ca-cert">
              <ActionForm action={importCaCertificate.bind(null, arn)} submit="Import" testId="import-ca-cert">
                <Field label="Certificate" rule={PEM_CERT}>
                  <textarea name="certificate" rows={6} required className="code-editor" spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" />
                </Field>
                <Field label="Certificate chain" rule={PEM_CHAIN}>
                  <textarea name="chain" rows={4} className="code-editor" spellCheck={false} />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {ca.Status === "ACTIVE" && (
            <Sheet title="Issue certificate" label="Issue certificate" icon={<FileSignature size={16} />} testId="issue-certificate">
              <ActionForm action={issueFromCsr.bind(null, arn)} submit="Issue" testId="issue-certificate">
                <Field label="CSR" rule={CSR} member="Csr">
                  <textarea name="csr" rows={8} required placeholder="-----BEGIN CERTIFICATE REQUEST-----" className="code-editor" />
                </Field>
                <div className="form-row">
                  <Field label="Template" member="TemplateArn">
                    <select name="template" defaultValue="EndEntityCertificate/V1">
                      {TEMPLATES.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.label}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Signature algorithm" member="SigningAlgorithm">
                    <select name="signing" defaultValue={cfg?.SigningAlgorithm}>
                      {signing.map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </Field>
                </div>
                <div className="form-row">
                  <Field label="Validity (days)" rule={days} member="Validity.Value" hint={caDays !== undefined ? `Up to ${maxDays}, when the CA ${ca.UsageMode === "SHORT_LIVED_CERTIFICATE" && maxDays === 7 ? "caps short-lived certificates" : "expires"}` : undefined}>
                    <input name="days" type="number" defaultValue={maxDays !== undefined ? Math.min(365, maxDays) : 365} />
                  </Field>
                  <Field label="Valid from" member="ValidityNotBefore">
                    <input name="notBefore" type="datetime-local" />
                  </Field>
                </div>
              </ActionForm>
            </Sheet>
          )}
          {(ca.Status === "ACTIVE" || ca.Status === "DISABLED") && (
            <Sheet title="Revoke certificate" label="Revoke certificate" icon={<Ban size={16} />} testId="revoke-certificate">
              <ActionForm action={revokeCertificate.bind(null, arn)} submit="Revoke" tone="danger" testId="revoke-certificate">
                <Field label="Certificate serial" rule={SERIAL} member="CertificateSerial">
                  <input name="serial" required placeholder="3e:1a:…" />
                </Field>
                <Field label="Reason" member="RevocationReason">
                  <select name="reason" defaultValue="UNSPECIFIED">
                    {REASONS.map((r) => (
                      <option key={r} value={r}>
                        {pretty(r)}
                      </option>
                    ))}
                  </select>
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {ca.Status === "ACTIVE" && <ActionForm action={setAuthorityStatus.bind(null, arn, "DISABLED")} submit="Disable CA" icon={<Pause size={16} />} />}
          {ca.Status === "DISABLED" && <ActionForm action={setAuthorityStatus.bind(null, arn, "ACTIVE")} submit="Enable CA" icon={<Play size={16} />} />}
          {ca.Status === "DELETED" ? (
            <ActionForm action={restoreAuthority.bind(null, arn)} submit="Restore CA" icon={<RotateCcw size={16} />} />
          ) : (
            ca.Status !== "ACTIVE" && (
              <Sheet title={`Delete ${name}`} label="Delete CA" icon={<Trash2 size={16} />} testId="delete-ca">
                <ActionForm action={deleteAuthority.bind(null, arn)} submit="Delete" tone="danger" testId="delete-ca">
                  <Field label="Restorable for (days)" rule={{ type: "integer", min: 7, max: 30, default: 30 }} member="PermanentDeletionTimeInDays">
                    <input name="days" type="number" defaultValue={30} />
                  </Field>
                </ActionForm>
              </Sheet>
            )
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
      {ca.Status === "FAILED" && <div className="banner error">{ca.FailureReason ? pretty(ca.FailureReason) : "Failed"}</div>}
      {pending && (
        <div className="banner">
          {ca.Type === "ROOT" ? "Install the CA certificate to start issuing." : parents.length ? "Sign this CA with a parent CA, or import a certificate signed elsewhere." : "Download the CSR, have it signed, and import the certificate."}
        </div>
      )}
      <Segments label="Certificate authority" items={tabs.map((t) => ({ label: t.label, href: t.id === "details" ? self : `${self}&tab=${t.id}`, active: t.id === active, count: t.count }))} />
      {body}
    </Page>
  );
}

/** A starting point: let another account issue from this CA (as RAM sharing needs). */
function template(arn: string) {
  const account = arn.split(":")[4];
  return JSON.stringify(
    {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "ShareIssuance",
          Effect: "Allow",
          Principal: { AWS: `arn:aws:iam::${account}:root` },
          Action: ["acm-pca:IssueCertificate", "acm-pca:GetCertificate", "acm-pca:DescribeCertificateAuthority", "acm-pca:GetCertificateAuthorityCertificate", "acm-pca:ListPermissions", "acm-pca:ListTags"],
          Resource: arn,
        },
      ],
    },
    null,
    2,
  );
}
