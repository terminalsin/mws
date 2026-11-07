import { inventoryResponse } from "@mws-dashboard/aws";

import { caches, databases, ecsClusters, eksClusters, fileSystems, repositories, streams } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

export async function GET() {
  return inventoryResponse([databases, caches, repositories, ecsClusters, eksClusters, fileSystems, streams]);
}
