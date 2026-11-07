import { inventoryResponse } from "@mws-dashboard/aws";

import { functions, instances } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

export async function GET() {
  return inventoryResponse([functions, instances]);
}
