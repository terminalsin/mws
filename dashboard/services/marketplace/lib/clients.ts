import "server-only";

import { MarketplaceEntitlementServiceClient } from "@aws-sdk/client-marketplace-entitlement-service";
import { MarketplaceMeteringClient } from "@aws-sdk/client-marketplace-metering";
import { client } from "@mws-dashboard/aws";

export const ICONS = {
  marketplace: "service/AWSMarketplace",
};

export type Tone = "good" | "warn" | "bad" | "neutral" | "info";

/** Words AWS uses for states, as tones. */
export function tone(status: string | undefined): Tone {
  const s = (status ?? "").toUpperCase();
  if (/FAIL|ERROR|CANCEL|UNHEALTHY|DEPRECATED|DELETED/.test(s)) return "bad";
  if (/PENDING|RUNNING|PROVISION|BUILD|CREAT|UPDAT|DELET|PROGRESS|TEST|DISTRIBUT|INTEGRAT|STARTING|CANCELLING|LEGACY/.test(s)) return "warn";
  if (/SUCCE|AVAILABLE|ACTIVE|HEALTHY|INSERVICE|COMPLETE|ENABLED|READY/.test(s)) return "good";
  return "neutral";
}
export const metering = () => client(MarketplaceMeteringClient);

export const entitlements = () => client(MarketplaceEntitlementServiceClient);
