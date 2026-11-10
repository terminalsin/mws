import "server-only";

import { ListEmailIdentitiesCommand } from "@aws-sdk/client-sesv2";
import { type InventoryItem } from "@mws-dashboard/aws";

import { ses } from "./clients";

export async function identityItems(): Promise<InventoryItem[]> {
  const out = await (await ses()).send(new ListEmailIdentitiesCommand({}));
  return (out.EmailIdentities ?? []).map((i) => ({
    service: "ses",
    type: i.IdentityType === "DOMAIN" ? "Domain identity" : "Email identity",
    id: `ses:${i.IdentityName}`,
    name: i.IdentityName!,
    href: "/ses",
    detail: i.VerificationStatus?.toLowerCase(),
  }));
}
