import "server-only";

import { ListHostedZonesByNameCommand, Route53Client } from "@aws-sdk/client-route-53";
import { GetIdentityVerificationAttributesCommand } from "@aws-sdk/client-ses";
import { GetEmailIdentityCommand } from "@aws-sdk/client-sesv2";
import { client, region } from "@mws-dashboard/aws";

import { ses, sesV1 } from "./clients";

const isDomain = (identity: string) => !identity.includes("@");

export type DnsRecord = { name: string; type: "TXT" | "CNAME" | "MX"; value: string; purpose: string };

/** The records a domain identity needs, as SES lists them. */
export async function identityRecords(identity: string) {
  const [v2, v1, here] = await Promise.all([
    (await ses()).send(new GetEmailIdentityCommand({ EmailIdentity: identity })),
    (await sesV1()).send(new GetIdentityVerificationAttributesCommand({ Identities: [identity] })).catch(() => undefined),
    region(),
  ]);
  const domain = identity.includes("@") ? identity.split("@")[1] : identity;
  const token = v1?.VerificationAttributes?.[identity]?.VerificationToken;
  const records: DnsRecord[] = [];
  if (isDomain(identity)) {
    if (token) records.push({ name: `_amazonses.${domain}`, type: "TXT", value: `"${token}"`, purpose: "Verification" });
    for (const t of v2.DkimAttributes?.SigningAttributesOrigin === "AWS_SES" || !v2.DkimAttributes?.SigningAttributesOrigin ? (v2.DkimAttributes?.Tokens ?? []) : [])
      records.push({ name: `${t}._domainkey.${domain}`, type: "CNAME", value: `${t}.dkim.amazonses.com`, purpose: "DKIM" });
  }
  const mailFrom = v2.MailFromAttributes?.MailFromDomain;
  if (mailFrom) {
    records.push({ name: mailFrom, type: "MX", value: `10 feedback-smtp.${here}.amazonses.com`, purpose: "MAIL FROM" });
    records.push({ name: mailFrom, type: "TXT", value: '"v=spf1 include:amazonses.com ~all"', purpose: "MAIL FROM (SPF)" });
  }
  return records;
}

/** The public hosted zone that holds `name`: the longest suffix match. */
export async function zoneFor(name: string) {
  const r53 = await client(Route53Client, { region: "us-east-1" });
  const labels = name.replace(/\.$/, "").split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = `${labels.slice(i).join(".")}.`;
    const out = await r53.send(new ListHostedZonesByNameCommand({ DNSName: candidate, MaxItems: 5 }));
    const zone = out.HostedZones?.find((z) => z.Name === candidate && !z.Config?.PrivateZone);
    if (zone) return zone;
  }
  return undefined;
}

