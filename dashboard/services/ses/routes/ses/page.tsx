import { GetAccountCommand, ListEmailIdentitiesCommand, type GetAccountCommandOutput, type IdentityInfo } from "@aws-sdk/client-sesv2";
import { ago, collect, load, type Loaded } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Metric, Metrics, Page, Pill, Section, Sheet, Status, type Rule } from "@mws-dashboard/ui";
import { CreateEmailIdentity, SendEmail } from "@mws-dashboard/ui/model/sesv2";
import { BadgeCheck, Eraser, Globe, Mail, Send, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ses } from "../../lib/clients";
import { sesMail } from "../../lib/outbox";
import { clearOutbox, createIdentity, deleteIdentity, sendEmail, verifyIdentity } from "./actions";

export const metadata: Metadata = { title: "SES" };

type Props = { searchParams: Promise<{ tab?: string }> };

const listIdentities = () =>
  load(async () => {
    const client = await ses();
    return collect(
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
function sendRules(identities: Loaded<IdentityInfo[]>, sandbox: boolean): { from: Rule; to: Rule } {
  const verified = identities.ok ? identities.value.filter((i) => i.VerificationStatus === "SUCCESS") : [];
  const emails = verified.filter((i) => i.IdentityType === "EMAIL_ADDRESS").map((i) => i.IdentityName!);
  const domains = verified.filter((i) => i.IdentityType === "DOMAIN").map((i) => i.IdentityName!);
  const senders = [...emails, ...domains.map((d) => `no-reply@${d}`)];
  const from: Rule = { ...SendEmail.FromEmailAddress, required: true, format: "email" };
  const to: Rule = { required: true, format: "emails" };
  if (!identities.ok) return { from, to };
  const one = verifiedAddress(emails, domains);
  const recipient = verifiedAddress(emails, [...domains, SIMULATOR]);
  return {
    from: one ? { ...from, pattern: `^(?:${one})$`, hint: "Not a verified identity", known: senders } : from,
    to: sandbox
      ? { ...to, pattern: `^(?:${recipient})(?:,\\s*(?:${recipient}))*$`, hint: "Sandbox: verified addresses only", known: [...emails, `success@${SIMULATOR}`] }
      : { ...to, known: emails },
  };
}

function SendEmailSheet({ identities, sandbox }: { identities: Loaded<IdentityInfo[]>; sandbox: boolean }) {
  const rules = sendRules(identities, sandbox);
  return (
    <Sheet title="Send email" label="Send email" icon={<Send size={15} aria-hidden />} testId="send-email">
      <ActionForm action={sendEmail} submit="Send" testId="send-email">
        <div className="form-row">
          <Field label="From" rule={rules.from} member="FromEmailAddress">
            <input name="from" required autoComplete="email" />
          </Field>
          <Field label="To" rule={rules.to} member="ToAddresses">
            <input name="to" required />
          </Field>
        </div>
        <Field label="Subject">
          <input name="subject" />
        </Field>
        <textarea name="body" aria-label="Body" />
      </ActionForm>
    </Sheet>
  );
}

function Identities({ identities, account }: { identities: Loaded<IdentityInfo[]>; account: Loaded<GetAccountCommandOutput> }) {
  return (
    <>
      {account.ok && (
        <Metrics>
          <Metric label="Sending" value={account.value.ProductionAccessEnabled ? "Production" : "Sandbox"} tone={account.value.ProductionAccessEnabled ? "good" : "warn"} />
          <Metric label="Sent in 24h" value={account.value.SendQuota?.SentLast24Hours ?? 0} />
          <Metric label="Daily quota" value={account.value.SendQuota?.Max24HourSend ?? "—"} />
        </Metrics>
      )}
      <Section
        title="Identities"
        plain
        actions={
          <Sheet title="New identity" label="Create identity" testId="create-identity">
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
                meta: <Status tone={verified ? "good" : "warn"}>{verified ? "verified" : (i.VerificationStatus?.toLowerCase() ?? "pending")}</Status>,
                actions: (
                  <>
                    {!verified && (
                      <ActionForm
                        action={verifyIdentity.bind(null, i.IdentityName!)}
                        submit={`Verify ${i.IdentityName}`}
                        icon={<BadgeCheck size={16} aria-hidden />}
                      />
                    )}
                    <ActionForm
                      action={deleteIdentity.bind(null, i.IdentityName!)}
                      submit={`Delete ${i.IdentityName}`}
                      icon={<Trash2 size={16} aria-hidden />}
                      tone="danger"
                      confirm={`Delete ${i.IdentityName}?`}
                    />
                  </>
                ),
              };
            })}
          />
        ) : (
          <ErrorNotice error={identities.error} />
        )}
      </Section>
    </>
  );
}

async function Outbox() {
  const outbox = await load(sesMail);
  if (!outbox.ok) return <ErrorNotice error={outbox.error} />;
  return (
    <Section
      title="Sent"
      count={outbox.value.length}
      plain
      actions={<ActionForm action={clearOutbox} submit="Clear" icon={<Eraser size={16} aria-hidden />} tone="danger" />}
    >
      <List
        label="Outbox"
        empty={<Empty icon={ICONS.email} />}
        rows={[...outbox.value].reverse().map((m) => ({
          key: m.Id,
          icon: <AwsIcon icon={ICONS.email} size={24} />,
          title: m.Subject || m.Template || "(no subject)",
          subtitle: (
            <details>
              <summary>
                {m.Source} → {m.Destination.ToAddresses.join(", ")}
              </summary>
              <pre className="code">{m.Body.text_part ?? m.Body.html_part ?? m.RawData}</pre>
            </details>
          ),
          meta: (
            <>
              {m.Kind !== "Email" && <Pill tone="info">{m.Kind}</Pill>}
              <span>{ago(m.Timestamp)}</span>
            </>
          ),
        }))}
      />
    </Section>
  );
}

export default async function Ses({ searchParams }: Props) {
  const tab = (await searchParams).tab ?? "identities";
  const [identities, account] = await Promise.all([listIdentities(), load(async () => (await ses()).send(new GetAccountCommand({})))]);
  const sandbox = !(account.ok && account.value.ProductionAccessEnabled);
  return (
    <Page title={tab === "outbox" ? "Sent mail" : "Identities"} actions={<SendEmailSheet identities={identities} sandbox={sandbox} />}>
      {tab === "outbox" ? <Outbox /> : <Identities identities={identities} account={account} />}
    </Page>
  );
}
