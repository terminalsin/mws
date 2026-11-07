import "server-only";

import { mws } from "@mws-dashboard/aws";

// What SNS and SES "sent" to people: MWS keeps it in outboxes under /_aws.

export interface SnsEmail {
  messageId: string;
  to: string;
  subject: string;
  body: string;
  topicArn: string;
  timestamp: string;
}

export interface SnsSms {
  messageId: string;
  phoneNumber: string;
  message: string;
  topicArn?: string | null;
  timestamp: string;
}

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
  Timestamp: string;
  Kind: string;
}

export async function snsEmails() {
  return (await mws<{ emailMessages: SnsEmail[] }>("/_aws/sns/email-messages")).emailMessages;
}

export async function snsSms() {
  return (await mws<{ smsMessages: SnsSms[] }>("/_aws/sns/sms-messages")).smsMessages;
}

export async function sesMail() {
  return (await mws<{ messages: SesMail[] }>("/_aws/ses")).messages;
}
