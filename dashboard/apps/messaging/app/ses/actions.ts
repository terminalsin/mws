"use server";

import { CreateEmailIdentityCommand, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { act, frameInfo, mws, region, required, text, type ActionResult } from "@mws-dashboard/aws";

import { ses } from "../../lib/clients";

export async function createIdentity(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const identity = required(form, "identity", "Email address or domain");
    await (await ses()).send(new CreateEmailIdentityCommand({ EmailIdentity: identity }));
    return `Created ${identity}; SES mailed it a verification link (see the outbox)`;
  }, "/ses");
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
  return act(async () => {
    const out = await (await ses()).send(
      new SendEmailCommand({
        FromEmailAddress: required(form, "from", "From"),
        Destination: { ToAddresses: required(form, "to", "To").split(",").map((s) => s.trim()) },
        Content: {
          Simple: {
            Subject: { Data: text(form, "subject") || "(no subject)" },
            Body: { Text: { Data: text(form, "body") } },
          },
        },
      }),
    );
    return `Sent ${out.MessageId}`;
  }, "/ses");
}

export async function clearOutbox() {
  return act(async () => {
    await mws("/_aws/ses", { method: "DELETE" });
    return "Cleared";
  }, "/ses");
}
