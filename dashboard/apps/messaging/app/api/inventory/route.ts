import { inventoryResponse } from "@mws-dashboard/aws";

import { eventItems, identityItems, queueItems, topicItems } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

export async function GET() {
  return inventoryResponse([queueItems, topicItems, eventItems, identityItems]);
}
