import "server-only";

import { ListEmailIdentitiesCommand } from "@aws-sdk/client-sesv2";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { identityHref, ses, verificationLabel } from "./clients";

export async function identityItems(): Promise<InventoryItem[]> {
  const client = await ses();
  const list = await all(
    (NextToken) => client.send(new ListEmailIdentitiesCommand({ NextToken })),
    (r) => r.EmailIdentities,
    (r) => r.NextToken,
  );
  return list.map((i) => ({
    service: "ses",
    type: i.IdentityType === "DOMAIN" ? "Domain identity" : "Email identity",
    id: `ses:${i.IdentityName}`,
    name: i.IdentityName!,
    href: identityHref(i.IdentityName),
    detail: verificationLabel(i.VerificationStatus),
  }));
}
