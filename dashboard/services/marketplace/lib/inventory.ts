import "server-only";

import { type InventoryItem } from "@mws-dashboard/aws";

import { products as catalog } from "./marketplace";

export async function products(): Promise<InventoryItem[]> {
  return (await catalog()).map((p) => ({ service: "marketplace", type: "Product", id: p.productCode, name: p.title || p.productCode, href: `/marketplace/product?code=${p.productCode}`, detail: p.productType }));
}
