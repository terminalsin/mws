import { inventoryResponse } from "@mws-dashboard/aws";

import { accounts, shares, stacks } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

export async function GET() {
  return inventoryResponse([stacks, accounts, shares]);
}
