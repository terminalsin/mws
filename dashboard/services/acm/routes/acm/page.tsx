import { GetAccountConfigurationCommand } from "@aws-sdk/client-acm";
import { ListCertificateAuthoritiesCommand } from "@aws-sdk/client-acm-pca";
import { all as every, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Curated, Empty, ErrorNotice, Field, Page, Pill, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { ImportCertificate, PutAccountConfiguration } from "@mws-dashboard/ui/model/acm";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { BellRing, CalendarClock, Upload } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, acm, daysUntil, pca } from "../../lib/clients";
import { CERT_TONE, listCertificates, statusText } from "../../lib/acm";
import { RequestFields } from "../../lib/request-fields";
import { importCertificate, requestCertificate, saveExpiryEvents } from "./actions";

export const metadata: Metadata = { title: "Certificate Manager" };

const PEM = {
  certificate: { ...ImportCertificate.Certificate, format: "certificate" },
  key: { ...ImportCertificate.PrivateKey, format: "privateKey" },
  chain: { ...ImportCertificate.CertificateChain, format: "certificates" },
} satisfies Record<string, Rule>;

export default async function Certificates() {
  const [certs, cas, config] = await Promise.all([
    load(listCertificates),
    load(async () => {
      const c = await pca();
      const list = await every((NextToken) => c.send(new ListCertificateAuthoritiesCommand({ NextToken })), (r) => r.CertificateAuthorities, (r) => r.NextToken);
      return list.filter((ca) => ca.Status === "ACTIVE");
    }),
    (await acm()).send(new GetAccountConfigurationCommand({})).then((r) => r.ExpiryEvents, () => undefined),
  ]);
  const request = (
    <Sheet title="Request certificate" label="Request certificate" testId="request-certificate">
      <ActionForm action={requestCertificate} submit="Request" testId="request-certificate">
        <RequestFields
          issuers={cas.ok ? cas.value.map((c) => ({ arn: c.Arn!, name: c.CertificateAuthorityConfiguration?.Subject?.CommonName ?? c.Arn!.split("/").pop()! })) : []}
        />
      </ActionForm>
    </Sheet>
  );
  const importSheet = (
    <Sheet title="Import certificate" label="Import certificate" icon={<Upload size={16} />} testId="import-certificate">
      <ActionForm action={importCertificate.bind(null, undefined)} submit="Import" testId="import-certificate">
        <Field label="Certificate body" rule={PEM.certificate}>
          <textarea name="certificate" rows={5} required placeholder="-----BEGIN CERTIFICATE-----" className="code-editor" spellCheck={false} />
        </Field>
        <Field label="Private key" rule={PEM.key}>
          <textarea name="key" rows={5} required placeholder="-----BEGIN PRIVATE KEY-----" className="code-editor" spellCheck={false} />
        </Field>
        <Field label="Certificate chain" rule={PEM.chain}>
          <textarea name="chain" rows={3} placeholder="-----BEGIN CERTIFICATE-----" className="code-editor" spellCheck={false} />
        </Field>
        <MoreFields>
          <Field label="Tags" format="tags">
            <textarea name="tags" rows={2} placeholder="team=web" />
          </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
  const actions = (
    <>
      <Sheet title="Expiry events" label="Expiry events" icon={<BellRing size={16} />} testId="expiry-events">
        <ActionForm action={saveExpiryEvents} submit="Save" testId="expiry-events">
          <Field label="Days before expiry" rule={PutAccountConfiguration.ExpiryEvents.fields!.DaysBeforeExpiry} member="ExpiryEvents.DaysBeforeExpiry" hint="When ACM starts sending daily expiry events to EventBridge">
            <input name="days" type="number" required defaultValue={config?.DaysBeforeExpiry ?? 45} />
          </Field>
        </ActionForm>
      </Sheet>
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
            subtitle: extra > 0 ? `${c.SubjectAlternativeNameSummaries!.filter((n) => n !== c.DomainName).slice(0, 3).join(", ")}${extra > 3 ? ` +${extra - 3}` : ""}` : undefined,
            href: `/acm/cert?arn=${encodeURIComponent(c.CertificateArn!)}`,
            meta: (
              <>
                {c.Type && c.Type !== "AMAZON_ISSUED" && <Pill>{c.Type === "IMPORTED" ? "Imported" : "Private"}</Pill>}
                {days !== undefined && (c.Type !== "AMAZON_ISSUED" || c.RenewalEligibility === "ELIGIBLE") && (
                  <Pill tone={days < 0 ? "bad" : days <= 30 ? "warn" : "neutral"} icon={<CalendarClock size={12} aria-hidden />} title="Expires">
                    {days >= 0 ? `${days}d` : "Expired"}
                  </Pill>
                )}
                {c.InUse && <Pill tone="info" title="In use">In use</Pill>}
                <Status tone={days !== undefined && days <= 30 && c.Status === "ISSUED" ? "warn" : (CERT_TONE[c.Status ?? ""] ?? "neutral")}>{statusText(c.Status)}</Status>
              </>
            ),
          };
        }}
      />
    </Page>
  );
}
