"use server";

import { CreateEmailIdentityCommand, DeleteEmailIdentityCommand, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { act, FieldError, frameInfo, mws, region, required, text, type ActionResult } from "@mws-dashboard/aws";

import { ses } from "../../lib/clients";

export async function createIdentity(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const identity = required(form, "identity", "Email address or domain");
    await (await ses()).send(new CreateEmailIdentityCommand({ EmailIdentity: identity }));
    return `Created ${identity}; SES mailed it a verification link (see the outbox)`;
  }, { revalidate: ["/ses"], fields: { EmailIdentity: "identity", BadRequestException: "identity" } });
}

/** Mark an identity verified without clicking the link or publishing DNS records. */
export async function verifyIdentity(identity: string) {
  return act(async () => {
    const { account } = await frameInfo();
    const q = new URLSearchParams({ identity, account: account ?? "", region: await region() });
    await mws(`/_aws/ses/verify-identity?${q}`, { method: "POST" });
    return `Verified ${identity}`;
  }, "/ses");
}

export async function sendEmail(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const from = required(form, "from", "From");
      const to = required(form, "to", "To")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      try {
        const out = await (await ses()).send(
          new SendEmailCommand({
            FromEmailAddress: from,
            Destination: { ToAddresses: to },
            Content: {
              Simple: {
                Subject: { Data: text(form, "subject") || "(no subject)" },
                Body: { Text: { Data: text(form, "body") } },
              },
            },
          }),
        );
        return `Sent ${out.MessageId}`;
      } catch (e) {
        throw unverified(e, from, to) ?? e;
      }
    },
    { revalidate: ["/ses"], fields: { FromEmailAddress: "from", ToAddresses: "to", MailFromDomainNotVerifiedException: "from" } },
  );
}

/** SES names the identities that failed its verified-sender check (and, in
 * the sandbox, recipient check): put that on the field they came from. */
function unverified(e: unknown, from: string, to: string[]): FieldError | null {
  if (!(e instanceof Error) || e.name !== "MessageRejected") return null;
  const failed = e.message.match(/failed the check in region [^:]+: (.+)$/)?.[1]?.split(/,\s*/) ?? [];
  if (!failed.length) return null;
  const lower = failed.map((f) => f.toLowerCase());
  if (lower.includes(from.toLowerCase())) return new FieldError("from", "Not a verified identity", "missing");
  const recipients = to.filter((t) => lower.includes(t.toLowerCase()));
  return new FieldError("to", `Sandbox: ${(recipients.length ? recipients : failed).join(", ")} not verified`, "missing");
}

export async function clearOutbox() {
  return act(async () => {
    await mws("/_aws/ses", { method: "DELETE" });
    return "Cleared";
  }, "/ses");
}

export async function deleteIdentity(identity: string) {
  return act(async () => {
    await (await ses()).send(new DeleteEmailIdentityCommand({ EmailIdentity: identity }));
    return `Deleted ${identity}`;
  }, "/ses");
}
