import { inventoryResponse } from "@mws-dashboard/aws";

import { accelerators, authorities, certificates, hostedZones, loadBalancers, vpcs } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

export async function GET() {
  return inventoryResponse([vpcs, hostedZones, loadBalancers, accelerators, certificates, authorities]);
}
