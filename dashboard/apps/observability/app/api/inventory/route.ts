import { inventoryResponse } from "@mws-dashboard/aws";

import { alarms, logGroups } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

export async function GET() {
  return inventoryResponse([logGroups, alarms]);
}
