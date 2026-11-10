"use server";

import { ChangeResourceRecordSetsCommand, ListResourceRecordSetsCommand, Route53Client, type ResourceRecordSet } from "@aws-sdk/client-route-53";
import { SetIdentityHeadersInNotificationsEnabledCommand, SetIdentityNotificationTopicCommand } from "@aws-sdk/client-ses";
import {
  CreateEmailIdentityCommand,
  CreateEmailIdentityPolicyCommand,
  DeleteEmailIdentityCommand,
  DeleteEmailIdentityPolicyCommand,
  DeleteSuppressedDestinationCommand,
  PutAccountDetailsCommand,
  PutAccountSendingAttributesCommand,
  PutAccountSuppressionAttributesCommand,
  PutEmailIdentityConfigurationSetAttributesCommand,
  PutEmailIdentityDkimAttributesCommand,
  PutEmailIdentityDkimSigningAttributesCommand,
  PutEmailIdentityFeedbackAttributesCommand,
  PutEmailIdentityMailFromAttributesCommand,
  PutSuppressedDestinationCommand,
  SendEmailCommand,
  type EmailContent,
  type SuppressionListReason,
} from "@aws-sdk/client-sesv2";
import { act, client, FieldError, frameInfo, mws, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { identityHref, ses, sesV1 } from "../../lib/clients";
import { identityRecords, zoneFor } from "../../lib/dns";
import { sesMail } from "../../lib/outbox";

const isDomain = (identity: string) => !identity.includes("@");
const addresses = (form: FormData, name: string) =>
  text(form, name)
    .split(/[,;\n]+/)
    .map((s) => s.trim())
    .filter(Boolean);

export async function createIdentity(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const identity = required(form, "identity", "Email address or domain");
    await (await ses()).send(new CreateEmailIdentityCommand({ EmailIdentity: identity, ConfigurationSetName: text(form, "configSet") || undefined }));
    if (isDomain(identity)) redirect(identityHref(identity));
    return `Created ${identity}; SES mailed it a verification link (see Sent mail)`;
  }, { revalidate: ["/ses"], fields: { EmailIdentity: "identity", BadRequestException: "identity", ConfigurationSetName: "configSet" } });
}

/** Mark an identity verified without clicking the link or publishing DNS
 * records: MWS's test shortcut, not an AWS action. */
export async function verifyIdentity(identity: string) {
  return act(async () => {
    const { account } = await frameInfo();
    const q = new URLSearchParams({ identity, account: account ?? "", region: await region() });
    await mws(`/_aws/ses/verify-identity?${q}`, { method: "POST" });
    return `Marked ${identity} verified`;
  }, "/ses", "/ses/identity");
}

export async function deleteIdentity(identity: string, back?: boolean) {
  return act(async () => {
    await (await ses()).send(new DeleteEmailIdentityCommand({ EmailIdentity: identity }));
    if (back) redirect("/ses");
    return `Deleted ${identity}`;
  }, "/ses");
}

/** Publish the identity's records in its Route 53 public hosted zone, as
 * the SES console does. TXT values already there are kept. */
export async function publishRecords(identity: string) {
  return act(async () => {
    const records = await identityRecords(identity);
    if (!records.length) throw new Error("This identity needs no DNS records");
    const domain = identity.includes("@") ? identity.split("@")[1] : identity;
    const zone = await zoneFor(domain);
    if (!zone) throw new Error(`No Route 53 public hosted zone holds ${domain}: create one, or publish the records with your DNS provider`);
    const r53 = await client(Route53Client, { region: "us-east-1" });
    const zoneId = zone.Id!.split("/").pop()!;
    // Group values by name and type, merging with what is already published.
    const sets = new Map<string, ResourceRecordSet>();
    for (const r of records) {
      const key = `${r.name}|${r.type}`;
      const set = sets.get(key) ?? { Name: `${r.name}.`, Type: r.type, TTL: 1800, ResourceRecords: [] };
      set.ResourceRecords!.push({ Value: r.value });
      sets.set(key, set);
    }
    for (const set of sets.values()) {
      if (set.Type !== "TXT" && set.Type !== "MX") continue;
      const existing = (await r53.send(new ListResourceRecordSetsCommand({ HostedZoneId: zoneId, StartRecordName: set.Name, StartRecordType: set.Type, MaxItems: 1 }))).ResourceRecordSets?.[0];
      if (existing && existing.Name === set.Name && existing.Type === set.Type && !existing.SetIdentifier) {
        const values = new Set(set.ResourceRecords!.map((v) => v.Value));
        set.ResourceRecords!.push(...(existing.ResourceRecords ?? []).filter((v) => !values.has(v.Value)));
        set.TTL = existing.TTL ?? set.TTL;
      }
    }
    await r53.send(new ChangeResourceRecordSetsCommand({ HostedZoneId: zoneId, ChangeBatch: { Comment: `SES records for ${identity}`, Changes: [...sets.values()].map((s) => ({ Action: "UPSERT", ResourceRecordSet: s })) } }));
    return `Published ${records.length} records in ${zone.Name}`;
  }, "/ses/identity");
}

export async function setDkimSigning(identity: string, enabled: boolean) {
  return act(async () => {
    await (await ses()).send(new PutEmailIdentityDkimAttributesCommand({ EmailIdentity: identity, SigningEnabled: enabled }));
    return enabled ? "DKIM signing on" : "DKIM signing off";
  }, "/ses/identity");
}

export async function setDkimKeyLength(identity: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const length = required(form, "keyLength", "Key length") as "RSA_1024_BIT" | "RSA_2048_BIT";
    await (await ses()).send(new PutEmailIdentityDkimSigningAttributesCommand({ EmailIdentity: identity, SigningAttributesOrigin: "AWS_SES", SigningAttributes: { NextSigningKeyLength: length } }));
    return `Next DKIM key: ${length === "RSA_2048_BIT" ? "2048" : "1024"}-bit`;
  }, { revalidate: ["/ses/identity"], fields: { NextSigningKeyLength: "keyLength" } });
}

export async function setMailFrom(identity: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const domain = text(form, "mailFrom");
    await (await ses()).send(
      new PutEmailIdentityMailFromAttributesCommand({
        EmailIdentity: identity,
        MailFromDomain: domain || undefined,
        BehaviorOnMxFailure: (text(form, "mxFailure") || "USE_DEFAULT_VALUE") as "USE_DEFAULT_VALUE" | "REJECT_MESSAGE",
      }),
    );
    return domain ? `MAIL FROM ${domain}` : "MAIL FROM domain removed";
  }, { revalidate: ["/ses/identity"], fields: { MailFromDomain: "mailFrom", BadRequestException: "mailFrom", BehaviorOnMxFailure: "mxFailure" } });
}

export async function setFeedback(identity: string, enabled: boolean) {
  return act(async () => {
    await (await ses()).send(new PutEmailIdentityFeedbackAttributesCommand({ EmailIdentity: identity, EmailForwardingEnabled: enabled }));
    return enabled ? "Feedback forwarding on" : "Feedback forwarding off";
  }, "/ses/identity");
}

const NOTIFICATIONS = ["Bounce", "Complaint", "Delivery"] as const;

/** One SNS topic (or none) per notification type, and whether each
 * includes the original headers (SES v1). */
export async function setNotifications(identity: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const v1 = await sesV1();
    for (const type of NOTIFICATIONS) {
      const topic = text(form, `topic:${type}`);
      if (topic !== text(form, `was:${type}`)) await v1.send(new SetIdentityNotificationTopicCommand({ Identity: identity, NotificationType: type, SnsTopic: topic || undefined }));
      if (topic) await v1.send(new SetIdentityHeadersInNotificationsEnabledCommand({ Identity: identity, NotificationType: type, Enabled: form.get(`headers:${type}`) === "on" }));
    }
    return "Notifications saved";
  }, { revalidate: ["/ses/identity"], fields: { SnsTopic: "topic:Bounce", InvalidSnsTopic: "topic:Bounce" } });
}

export async function setIdentityConfigSet(identity: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = text(form, "configSet");
    await (await ses()).send(new PutEmailIdentityConfigurationSetAttributesCommand({ EmailIdentity: identity, ConfigurationSetName: name || undefined }));
    return name ? `Default configuration set ${name}` : "No default configuration set";
  }, { revalidate: ["/ses/identity"], fields: { ConfigurationSetName: "configSet", NotFoundException: "configSet" } });
}

export async function createIdentityPolicy(identity: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "policyName", "Policy name");
    await (await ses()).send(new CreateEmailIdentityPolicyCommand({ EmailIdentity: identity, PolicyName: name, Policy: required(form, "policy", "Policy") }));
    return `Policy ${name} created`;
  }, { revalidate: ["/ses/identity"], fields: { PolicyName: "policyName", Policy: "policy", BadRequestException: "policy", AlreadyExistsException: "policyName" } });
}

export async function deleteIdentityPolicy(identity: string, name: string) {
  return act(async () => {
    await (await ses()).send(new DeleteEmailIdentityPolicyCommand({ EmailIdentity: identity, PolicyName: name }));
    return `Deleted ${name}`;
  }, "/ses/identity");
}

/** `k=v` pairs, one per line or comma separated. */
function messageTags(form: FormData) {
  return text(form, "tags")
    .split(/[\n,]+/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [Name, ...rest] = l.split("=");
      if (!Name || !rest.length) throw new FieldError("tags", `${l}: like campaign=spring`, "format");
      return { Name: Name.trim(), Value: rest.join("=").trim() };
    });
}

export async function sendEmail(_: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const from = required(form, "from", "From");
      const to = addresses(form, "to");
      if (!to.length) throw new FieldError("to", "To is required", "required");
      const cc = addresses(form, "cc");
      const bcc = addresses(form, "bcc");
      const replyTo = addresses(form, "replyTo");
      const template = text(form, "template");
      const html = text(form, "html");
      const content: EmailContent = template
        ? { Template: { TemplateName: template, TemplateData: text(form, "templateData") || "{}" } }
        : {
            Simple: {
              Subject: { Data: text(form, "subject") || "(no subject)" },
              Body: { Text: { Data: text(form, "body") }, ...(html ? { Html: { Data: html } } : {}) },
            },
          };
      const tags = messageTags(form);
      try {
        const out = await (await ses()).send(
          new SendEmailCommand({
            FromEmailAddress: from,
            Destination: { ToAddresses: to, CcAddresses: cc.length ? cc : undefined, BccAddresses: bcc.length ? bcc : undefined },
            ReplyToAddresses: replyTo.length ? replyTo : undefined,
            ConfigurationSetName: text(form, "configSet") || undefined,
            EmailTags: tags.length ? tags : undefined,
            Content: content,
          }),
        );
        return `Sent ${out.MessageId}`;
      } catch (e) {
        throw unverified(e, from, [...to, ...cc, ...bcc]) ?? e;
      }
    },
    {
      revalidate: ["/ses"],
      fields: {
        FromEmailAddress: "from",
        ToAddresses: "to",
        CcAddresses: "cc",
        BccAddresses: "bcc",
        ReplyToAddresses: "replyTo",
        MailFromDomainNotVerifiedException: "from",
        ConfigurationSetName: "configSet",
        TemplateName: "template",
        TemplateData: "templateData",
        EmailTags: "tags",
      },
    },
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

/** Clear this account's and Region's mail only: the outbox is shared. */
export async function clearOutbox() {
  return act(async () => {
    const mine = await sesMail();
    await Promise.all(mine.map((m) => mws(`/_aws/ses?id=${encodeURIComponent(m.Id)}`, { method: "DELETE" })));
    return `Cleared ${mine.length}`;
  }, "/ses");
}

export async function deleteMail(id: string) {
  return act(async () => {
    await mws(`/_aws/ses?id=${encodeURIComponent(id)}`, { method: "DELETE" });
    return "Deleted";
  }, "/ses");
}

// Account.

export async function requestProduction(_: ActionResult | null, form: FormData) {
  return act(async () => {
    await (await ses()).send(
      new PutAccountDetailsCommand({
        MailType: (text(form, "mailType") || "TRANSACTIONAL") as "TRANSACTIONAL" | "MARKETING",
        WebsiteURL: required(form, "website", "Website URL"),
        UseCaseDescription: text(form, "useCase") || undefined,
        ContactLanguage: (text(form, "language") || "EN") as "EN" | "JA",
        ProductionAccessEnabled: true,
      }),
    );
    return "Production access requested";
  }, { revalidate: ["/ses"], fields: { WebsiteURL: "website", UseCaseDescription: "useCase", MailType: "mailType" } });
}

export async function setAccountSending(enabled: boolean) {
  return act(async () => {
    await (await ses()).send(new PutAccountSendingAttributesCommand({ SendingEnabled: enabled }));
    return enabled ? "Sending resumed" : "Sending paused";
  }, "/ses");
}

// Suppression list.

export async function suppress(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const email = required(form, "email", "Email address");
    await (await ses()).send(new PutSuppressedDestinationCommand({ EmailAddress: email, Reason: (text(form, "reason") || "BOUNCE") as SuppressionListReason }));
    return `Suppressed ${email}`;
  }, { revalidate: ["/ses"], fields: { EmailAddress: "email", BadRequestException: "email", Reason: "reason" } });
}

export async function unsuppress(email: string) {
  return act(async () => {
    await (await ses()).send(new DeleteSuppressedDestinationCommand({ EmailAddress: email }));
    return `Removed ${email}`;
  }, "/ses");
}

export async function setAccountSuppression(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const reasons = form.getAll("reason").filter((r): r is SuppressionListReason => r === "BOUNCE" || r === "COMPLAINT");
    await (await ses()).send(new PutAccountSuppressionAttributesCommand({ SuppressedReasons: reasons }));
    return reasons.length ? `Suppressing ${reasons.map((r) => r.toLowerCase()).join(" and ")}s` : "Suppression off";
  }, "/ses");
}
