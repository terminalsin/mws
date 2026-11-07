import { inventoryResponse } from "@mws-dashboard/aws";

import { keys, parameters, principals, secretItems } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

export async function GET() {
  return inventoryResponse([principals, keys, secretItems, parameters]);
}
