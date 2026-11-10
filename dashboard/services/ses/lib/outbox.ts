import "server-only";

import { frameInfo, mws } from "@mws-dashboard/aws";

// What SNS and SES "sent" to people: MWS keeps it in outboxes under /_aws.

export interface SesMail {
  Id: string;
  Region: string;
  AccountId: string;
  Source: string;
  Destination: { ToAddresses: string[]; CcAddresses?: string[]; BccAddresses?: string[] };
  Subject: string;
  Body: { text_part?: string | null; html_part?: string | null };
  RawData: string;
  Template?: string;
  TemplateData?: string;
  ConfigurationSetName?: string;
  Tags?: Record<string, string>;
  Timestamp: string;
  Kind: string;
  VerificationLink?: string;
}

export interface ReceivedMail {
  MessageId: string;
  AccountId: string;
  Region: string;
  Timestamp: string;
  Source: string;
  Recipients: string[];
  Subject: string;
  RuleSet: string;
  MatchedRules: string[];
  Actions: string[];
  RawData: string;
}

/** The outbox holds every account's and Region's mail: show this frame's. */
export async function sesMail() {
  const [{ messages }, { account, region }] = await Promise.all([mws<{ messages: SesMail[] }>("/_aws/ses"), frameInfo()]);
  return messages.filter((m) => (!account || m.AccountId === account) && (!region || m.Region === region));
}

export async function receivedMail() {
  const [{ messages }, { account, region }] = await Promise.all([mws<{ messages: ReceivedMail[] }>("/_aws/ses/inbound"), frameInfo()]);
  return messages.filter((m) => (!account || m.AccountId === account) && (!region || m.Region === region));
}

/** An HTML part as readable text, for mail without a text part. */
export function htmlText(html: string) {
  return html
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, "")
    .replace(/<br\s*\/?>|<\/(p|div|h\d|li|tr)>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
