import { GetAccountCommand, ListEmailIdentitiesCommand } from "@aws-sdk/client-sesv2";
import { ago, collect, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Metric, Metrics, Page, Pill, Section, Sheet, Status } from "@mws-dashboard/ui";
import { BadgeCheck, Eraser, Globe, Mail, Send, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ses } from "../../lib/clients";
import { sesMail } from "../../lib/outbox";
import { clearOutbox, createIdentity, deleteIdentity, sendEmail, verifyIdentity } from "./actions";

export const metadata: Metadata = { title: "SES" };

type Props = { searchParams: Promise<{ tab?: string }> };

async function Identities() {
  const [identities, account] = await Promise.all([
    load(async () => {
      const client = await ses();
      return collect(
        (NextToken) => client.send(new ListEmailIdentitiesCommand({ NextToken })),
        (r) => r.EmailIdentities,
        (r) => r.NextToken,
      );
    }),
    load(async () => (await ses()).send(new GetAccountCommand({}))),
  ]);
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
              <Field label="Email address or domain">
                <input name="identity" required />
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
  return (
    <Page
      title={tab === "outbox" ? "Sent mail" : "Identities"}
      actions={
        <Sheet title="Send email" label="Send email" icon={<Send size={15} aria-hidden />} testId="send-email">
          <ActionForm action={sendEmail} submit="Send" testId="send-email">
            <div className="form-row">
              <Field label="From">
                <input name="from" required />
              </Field>
              <Field label="To">
                <input name="to" required />
              </Field>
            </div>
            <Field label="Subject">
              <input name="subject" />
            </Field>
            <textarea name="body" aria-label="Body" />
          </ActionForm>
        </Sheet>
      }
    >
      {tab === "outbox" ? <Outbox /> : <Identities />}
    </Page>
  );
}
