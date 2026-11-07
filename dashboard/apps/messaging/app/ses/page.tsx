import { ListEmailIdentitiesCommand } from "@aws-sdk/client-sesv2";
import { collect, load, when } from "@mws-dashboard/aws";
import { ActionForm, Badge, ErrorNotice, Field, PageHeader, Section, Table } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { ses } from "../../lib/clients";
import { sesMail } from "../../lib/outbox";
import { clearOutbox, createIdentity, sendEmail, verifyIdentity } from "./actions";

export const metadata: Metadata = { title: "SES mail" };

export default async function Mail() {
  const [identities, outbox] = await Promise.all([
    load(async () => {
      const client = await ses();
      return collect(
        (NextToken) => client.send(new ListEmailIdentitiesCommand({ NextToken })),
        (r) => r.EmailIdentities,
        (r) => r.NextToken,
      );
    }),
    load(sesMail),
  ]);
  return (
    <>
      <PageHeader title="SES mail" description="Sending identities, and every message SES has sent (it never leaves your machine)." />
      <Section title="Identities">
        {identities.ok ? (
          <Table
            label="Identities"
            rows={identities.value}
            rowKey={(i) => i.IdentityName!}
            empty="No identities. Create one to send mail from it."
            columns={[
              { header: "Identity", cell: (i) => i.IdentityName },
              { header: "Type", cell: (i) => i.IdentityType?.toLowerCase().replace("_", " ") },
              {
                header: "Status",
                cell: (i) => (
                  <Badge tone={i.VerificationStatus === "SUCCESS" ? "good" : "warn"}>{i.VerificationStatus?.toLowerCase()}</Badge>
                ),
              },
              {
                header: "",
                cell: (i) =>
                  i.VerificationStatus !== "SUCCESS" && (
                    <ActionForm action={verifyIdentity.bind(null, i.IdentityName!)} submit="Mark verified" inline />
                  ),
              },
            ]}
          />
        ) : (
          <ErrorNotice error={identities.error} />
        )}
        <div style={{ marginTop: 12 }}>
          <ActionForm action={createIdentity} submit="Create identity" inline testId="create-identity">
            <Field label="Email address or domain">
              <input name="identity" required />
            </Field>
          </ActionForm>
        </div>
      </Section>
      <Section title="Send a test email">
        <ActionForm action={sendEmail} submit="Send" testId="send-email">
          <div className="form-row">
            <Field label="From">
              <input name="from" required />
            </Field>
            <Field label="To" hint="Comma-separated">
              <input name="to" required />
            </Field>
            <Field label="Subject">
              <input name="subject" />
            </Field>
          </div>
          <Field label="Body">
            <textarea name="body" />
          </Field>
        </ActionForm>
      </Section>
      <Section title="Outbox" actions={<ActionForm action={clearOutbox} submit="Clear" tone="danger" inline />}>
        {outbox.ok ? (
          <Table
            label="Outbox"
            rows={[...outbox.value].reverse()}
            rowKey={(m) => m.Id}
            empty="SES has not sent anything yet."
            columns={[
              { header: "Sent", cell: (m) => when(m.Timestamp) },
              { header: "From", cell: (m) => m.Source },
              { header: "To", className: "wrap", cell: (m) => m.Destination.ToAddresses.join(", ") },
              { header: "Kind", cell: (m) => <Badge tone={m.Kind === "Email" ? "neutral" : "info"}>{m.Kind}</Badge> },
              {
                header: "Message",
                className: "wrap",
                cell: (m) => (
                  <details>
                    <summary>{m.Subject || m.Template || "(no subject)"}</summary>
                    <pre className="code">{m.Body.text_part ?? m.Body.html_part ?? m.RawData}</pre>
                  </details>
                ),
              },
            ]}
          />
        ) : (
          <ErrorNotice error={outbox.error} />
        )}
      </Section>
    </>
  );
}
