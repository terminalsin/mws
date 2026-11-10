import "server-only";

import { mws } from "@mws-dashboard/aws";

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
  Timestamp: string;
  Kind: string;
}

export async function sesMail() {
  return (await mws<{ messages: SesMail[] }>("/_aws/ses")).messages;
}
