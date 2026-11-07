import { inventoryResponse } from "@mws-dashboard/aws";

import { apps, groups, guardrails, pipelines, products, repositories } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

export async function GET() {
  return inventoryResponse([guardrails, apps, repositories, pipelines, groups, products]);
}
