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

export async function snsEmails() {
  return (await mws<{ emailMessages: SnsEmail[] }>("/_aws/sns/email-messages")).emailMessages;
}

export async function snsSms() {
  return (await mws<{ smsMessages: SnsSms[] }>("/_aws/sns/sms-messages")).smsMessages;
}

export interface SnsPush {
  messageId: string;
  endpointArn: string;
  platform: string;
  token: string;
  message: string;
  topicArn?: string | null;
  timestamp: string;
}

export async function snsPush() {
  return (await mws<{ platformEndpointMessages: SnsPush[] }>("/_aws/sns/platform-endpoint-messages")).platformEndpointMessages;
}
