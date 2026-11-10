import { DescribeCertificateCommand, GetCertificateCommand, ListTagsForCertificateCommand } from "@aws-sdk/client-acm";
import { load, when } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, List, Page, Pill, Section, Specs, Status, Tags } from "@mws-dashboard/ui";
import { CalendarClock, KeyRound, Link2, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, acm, daysUntil } from "../../../lib/clients";
import { CERT_TONE, statusText } from "../../../lib/acm";
import { deleteCertificate, renewCertificate } from "../actions";

export const metadata: Metadata = { title: "Certificate" };

type Props = { searchParams: Promise<{ arn?: string }> };

function usedBy(arn: string) {
  const [, , service, , , resource] = arn.split(":");
  const icon = service === "elasticloadbalancing" ? ICONS.alb : service === "cloudfront" ? "service/AmazonCloudFront" : service === "apigateway" ? "service/AmazonAPIGateway" : ICONS.acm;
  const name = resource?.split("/").slice(-2, -1)[0] ?? resource ?? arn;
  const href = service === "elasticloadbalancing" && resource?.startsWith("loadbalancer/") ? `/elb/lb?arn=${encodeURIComponent(arn)}` : undefined;
  return { icon, name, href };
}

export default async function Certificate({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/acm", label: "Certificates" };
  const data = await load(async () => {
    const client = await acm();
    const [d, pem, tags] = await Promise.all([
      client.send(new DescribeCertificateCommand({ CertificateArn: arn })).then((r) => r.Certificate!),
      client.send(new GetCertificateCommand({ CertificateArn: arn })).then((r) => r.Certificate, () => undefined),
      client.send(new ListTagsForCertificateCommand({ CertificateArn: arn })).then((r) => r.Tags, () => undefined),
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
  const validations = (d.DomainValidationOptions ?? []).filter((v) => v.ResourceRecord || v.ValidationEmails?.length);
  return (
    <Page
      title={d.DomainName}
      icon={d.Type === "PRIVATE" ? ICONS.ca : ICONS.acm}
      back={back}
      subtitle={arn}
      actions={
        <>
          {d.RenewalEligibility === "ELIGIBLE" && d.Type === "PRIVATE" && <ActionForm action={renewCertificate.bind(null, arn)} submit="Renew" icon={<RefreshCw size={16} />} />}
          <ActionForm action={deleteCertificate.bind(null, arn)} submit="Delete certificate" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${d.DomainName}?`} testId="delete-certificate" />
        </>
      }
    >
      <Specs
        items={[
          { label: "Status", icon: <ShieldCheck size={15} />, value: <Status tone={CERT_TONE[d.Status ?? ""] ?? "neutral"}>{statusText(d.Status)}</Status> },
          d.NotAfter && { label: "Expires", icon: <CalendarClock size={15} />, value: <span className={days !== undefined && days <= 30 ? "tone-warn" : undefined}>{when(d.NotAfter)}{days !== undefined && days >= 0 ? ` · ${days}d` : ""}</span> },
          { label: "Key algorithm", icon: <KeyRound size={15} />, value: d.KeyAlgorithm?.replace(/_/g, " ").replace("EC prime256v1", "ECDSA P-256") },
          d.Issuer && { label: "Issuer", icon: <AwsIcon icon={d.Type === "PRIVATE" ? ICONS.ca : ICONS.acm} size={16} />, value: d.Issuer },
          d.Type && d.Type !== "AMAZON_ISSUED" && { label: "Type", icon: <Link2 size={15} />, value: d.Type === "IMPORTED" ? "Imported" : "Private" },
          d.RenewalSummary && { label: "Renewal", icon: <RefreshCw size={15} />, value: statusText(d.RenewalSummary.RenewalStatus) },
        ]}
      />
      {d.FailureReason && <div className="banner error">{statusText(d.FailureReason)}</div>}
      {validations.length > 0 && (
        <Section title="Domains" count={d.DomainValidationOptions?.length} plain>
          <List
            label="Domains"
            rows={(d.DomainValidationOptions ?? []).map((v) => ({
              key: v.DomainName!,
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
            }))}
          />
        </Section>
      )}
      {d.InUseBy && d.InUseBy.length > 0 && (
        <Section title="In use by" count={d.InUseBy.length} plain>
          <List
            label="In use by"
            rows={d.InUseBy.map((a) => {
              const u = usedBy(a);
              return { key: a, icon: <AwsIcon icon={u.icon} size={22} />, title: u.name, subtitle: a, href: u.href };
            })}
          />
        </Section>
      )}
      {d.SubjectAlternativeNames && d.SubjectAlternativeNames.length > 1 && validations.length === 0 && (
        <Section title="Names">
          <div className="chips">
            {d.SubjectAlternativeNames.map((n) => (
              <Pill key={n}>{n}</Pill>
            ))}
          </div>
        </Section>
      )}
      {pem && (
        <details>
          <summary>Certificate body</summary>
          <CodeBlock value={pem} label="Certificate body" />
        </details>
      )}
      <Tags tags={tags} />
    </Page>
  );
}
