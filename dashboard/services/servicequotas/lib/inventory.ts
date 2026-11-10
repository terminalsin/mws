import "server-only";

import { ListRequestedServiceQuotaChangeHistoryCommand } from "@aws-sdk/client-service-quotas";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { quotas } from "./clients";
import { OPEN, statusWord } from "./quotas";

/** Open increase requests: what Service Quotas has in flight. */
export async function requests(): Promise<InventoryItem[]> {
  const c = await quotas();
  const list = (
    await Promise.all(
      [...OPEN].map((Status) => all((NextToken) => c.send(new ListRequestedServiceQuotaChangeHistoryCommand({ Status: Status as "PENDING", NextToken })), (r) => r.RequestedQuotas, (r) => r.NextToken)),
    )
  ).flat();
  return list.map((r) => ({
    service: "servicequotas",
    type: "Quota increase request",
    id: `servicequotas:request:${r.Id}`,
    name: r.QuotaName ?? r.QuotaCode!,
    href: `/servicequotas/quota?service=${r.ServiceCode}&code=${r.QuotaCode}`,
    detail: `${r.ServiceName}: ${r.DesiredValue} (${statusWord(r.Status)})`,
  }));
}
