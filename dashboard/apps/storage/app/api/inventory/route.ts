import { inventoryResponse } from "@mws-dashboard/aws";

import { buckets } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

export async function GET() {
  return inventoryResponse([buckets]);
}
