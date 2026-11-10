import { ListEmailIdentitiesCommand, type IdentityInfo } from "@aws-sdk/client-sesv2";
import { all, load, type Loaded } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, List, Page, Section, Segments, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { MoreFields } from "@mws-dashboard/ui/presets";
import { CreateEmailIdentity, SendEmail } from "@mws-dashboard/ui/model/sesv2";
import { BadgeCheck, Globe, Mail, Send, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { configSets, templates } from "../../lib/choices";
import { ICONS, identityHref, ses, VERIFICATION_TONE, verificationLabel } from "../../lib/clients";
import { AccountPanel, accountOf, ConfigSets, Outbox, Receiving, Suppression, Templates } from "./tabs";
import { createIdentity, deleteIdentity, sendEmail, verifyIdentity } from "./actions";

export const metadata: Metadata = { title: "SES" };

type Props = { searchParams: Promise<{ tab?: string }> };

const TABS = [
  { id: "identities", label: "Identities", title: "Identities" },
  { id: "configsets", label: "Configuration sets", title: "Configuration sets" },
  { id: "templates", label: "Email templates", title: "Email templates" },
  { id: "receiving", label: "Email receiving", title: "Email receiving" },
  { id: "suppression", label: "Suppression list", title: "Suppression list" },
  { id: "outbox", label: "Sent mail", title: "Sent mail" },
];

const listIdentities = () =>
  load(async () => {
    const client = await ses();
    return all(
      (NextToken) => client.send(new ListEmailIdentitiesCommand({ NextToken })),
      (r) => r.EmailIdentities,
      (r) => r.NextToken,
    );
  });

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const SIMULATOR = "simulator.amazonses.com";

/** A pattern for one address SES accepts as verified: a verified address,
 * or any address on a verified domain. */
function verifiedAddress(emails: string[], domains: string[]): string {
  return [...emails.map(escape), ...(domains.length ? [`[^@\\s,]+@(?:${domains.map(escape).join("|")})`] : [])].join("|");
}

/** The send sheet's rules: SES sends only from verified identities and, in
 * the sandbox, only to verified addresses (or the mailbox simulator). */
function sendRules(identities: Loaded<IdentityInfo[]>, sandbox: boolean): { from: Rule; to: Rule; cc: Rule } {
  const verified = identities.ok ? identities.value.filter((i) => i.VerificationStatus === "SUCCESS") : [];
  const emails = verified.filter((i) => i.IdentityType === "EMAIL_ADDRESS").map((i) => i.IdentityName!);
  const domains = verified.filter((i) => i.IdentityType === "DOMAIN").map((i) => i.IdentityName!);
  const senders = [...emails, ...domains.map((d) => `no-reply@${d}`)];
  const from: Rule = { ...SendEmail.FromEmailAddress, required: true, format: "email" };
  const to: Rule = { required: true, format: "emails" };
  const cc: Rule = { format: "emails" };
  if (!identities.ok) return { from, to, cc };
  const one = verifiedAddress(emails, domains);
  const recipient = verifiedAddress(emails, [...domains, SIMULATOR]);
  const list = `^(?:${recipient})(?:,\\s*(?:${recipient}))*$`;
  return {
    from: one ? { ...from, pattern: `^(?:${one})$`, hint: "Not a verified identity", known: senders } : from,
    to: sandbox ? { ...to, pattern: list, hint: "Sandbox: verified addresses only", known: [...emails, `success@${SIMULATOR}`] } : { ...to, known: emails },
    cc: sandbox ? { ...cc, pattern: list, hint: "Sandbox: verified addresses only", known: emails } : { ...cc, known: emails },
  };
}

async function SendEmailSheet({ identities, sandbox }: { identities: Loaded<IdentityInfo[]>; sandbox: boolean }) {
  const rules = sendRules(identities, sandbox);
  const [sets, temps] = await Promise.all([configSets(), templates()]);
  return (
    <Sheet title="Send test email" label="Send email" icon={<Send size={15} aria-hidden />} testId="send-email">
      <ActionForm action={sendEmail} submit="Send" testId="send-email">
        <div className="form-row">
          <Field label="From" rule={rules.from} member="FromEmailAddress">
            <input name="from" required autoComplete="email" defaultValue={rules.from.known?.[0]} />
          </Field>
          <Field label="To" rule={rules.to} member="ToAddresses">
            <input name="to" required defaultValue={sandbox ? `success@${SIMULATOR}` : undefined} />
          </Field>
        </div>
        {temps.length > 0 && (
          <div className="form-row">
            <Field label="Template" member="TemplateName" hint="A template replaces subject and body">
              <select name="template" defaultValue="">
                <option value="">None (write the message)</option>
                {temps.map((t) => (
                  <option key={t.TemplateName}>{t.TemplateName}</option>
                ))}
              </select>
            </Field>
            <Field label="Template data" format="json" member="TemplateData">
              <input name="templateData" placeholder='{"name":"Ana"}' />
            </Field>
          </div>
        )}
        <Field label="Subject">
          <input name="subject" />
        </Field>
        <textarea name="body" aria-label="Body" />
        {sets.length > 0 && (
          <Field label="Configuration set" member="ConfigurationSetName">
            <select name="configSet" defaultValue="">
              <option value="">Identity default</option>
              {sets.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </Field>
        )}
        <MoreFields label="Cc, Bcc, HTML, tags">
          <div className="form-row">
            <Field label="Cc" rule={rules.cc} member="CcAddresses">
              <input name="cc" />
            </Field>
            <Field label="Bcc" rule={rules.cc} member="BccAddresses">
              <input name="bcc" />
            </Field>
            <Field label="Reply-To" rule={{ format: "emails" }} member="ReplyToAddresses">
              <input name="replyTo" />
            </Field>
          </div>
          <Field label="HTML body">
            <textarea name="html" rows={3} className="code-editor" />
          </Field>
          <Field label="Message tags (name=value)" rule={{ pattern: "^\\s*([\\w-]+=[\\w.@-]*\\s*(,\\s*|$))*$", hint: "Like campaign=spring" }} member="EmailTags">
            <input name="tags" />
          </Field>
        </MoreFields>
      </ActionForm>
    </Sheet>
  );
}

function Identities({ identities }: { identities: Loaded<IdentityInfo[]> }) {
  const pending = identities.ok && identities.value.some((i) => i.VerificationStatus === "PENDING");
  return (
    <Section
      title="Identities"
      count={identities.ok ? identities.value.length : undefined}
      plain
      actions={
        <Sheet title="Create identity" label="Create identity" testId="create-identity">
          <ActionForm action={createIdentity} submit="Create" testId="create-identity">
            <Field
              label="Email address or domain"
              rule={CreateEmailIdentity.EmailIdentity}
              format="email-or-domain"
              taken={identities.ok ? identities.value.map((i) => i.IdentityName!) : undefined}
              member="EmailIdentity"
              unique
            >
              <input name="identity" required autoComplete="off" />
            </Field>
          </ActionForm>
        </Sheet>
      }
    >
      {pending && <LiveRefresh />}
      {identities.ok ? (
        <List
          label="Identities"
          empty={<Empty icon={ICONS.email} />}
          rows={identities.value.map((i) => {
            const verified = i.VerificationStatus === "SUCCESS";
            return {
              key: i.IdentityName!,
              icon: i.IdentityType === "DOMAIN" ? <Globe size={18} aria-hidden /> : <Mail size={18} aria-hidden />,
              title: i.IdentityName,
              href: identityHref(i.IdentityName),
              meta: <Status tone={VERIFICATION_TONE[i.VerificationStatus ?? "PENDING"] ?? "warn"}>{verificationLabel(i.VerificationStatus)}</Status>,
              actions: (
                <>
                  {!verified && (
                    <ActionForm
                      action={verifyIdentity.bind(null, i.IdentityName!)}
                      submit={`Verify ${i.IdentityName} (MWS shortcut: skips the link or DNS records)`}
                      icon={<BadgeCheck size={16} aria-hidden />}
                    />
                  )}
                  <ActionForm action={deleteIdentity.bind(null, i.IdentityName!, false)} submit={`Delete ${i.IdentityName}`} icon={<Trash2 size={16} aria-hidden />} tone="danger" confirm={`Delete ${i.IdentityName}?`} />
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={identities.error} />
      )}
    </Section>
  );
}

export default async function Ses({ searchParams }: Props) {
  const requested = (await searchParams).tab ?? "identities";
  const tab = TABS.find((t) => t.id === requested) ?? TABS[0];
  const [identities, account] = await Promise.all([listIdentities(), accountOf()]);
  const sandbox = !(account.ok && account.value.ProductionAccessEnabled);
  return (
    <Page title={tab.title} actions={<SendEmailSheet identities={identities} sandbox={sandbox} />}>
      <Segments label="SES" items={TABS.map((t) => ({ label: t.label, href: t.id === "identities" ? "/ses" : `/ses?tab=${t.id}`, active: t.id === tab.id }))} />
      {tab.id === "identities" && (
        <>
          {account.ok && <AccountPanel account={account.value} />}
          <Identities identities={identities} />
        </>
      )}
      {tab.id === "configsets" && <ConfigSets />}
      {tab.id === "templates" && <Templates />}
      {tab.id === "receiving" && <Receiving />}
      {tab.id === "suppression" && <Suppression account={account.ok ? account.value : null} />}
      {tab.id === "outbox" && <Outbox />}
    </Page>
  );
}
