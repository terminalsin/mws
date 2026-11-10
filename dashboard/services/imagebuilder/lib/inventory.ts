import "server-only";

import { type InventoryItem } from "@mws-dashboard/aws";

import * as lists from "./lists";

const enc = encodeURIComponent;

export async function pipelines(): Promise<InventoryItem[]> {
  return (await lists.pipelines()).map((p) => ({ service: "imagebuilder", type: "Image pipeline", id: p.arn!, name: p.name!, href: `/imagebuilder/pipeline?arn=${enc(p.arn!)}`, tags: p.tags }));
}

export async function recipes(): Promise<InventoryItem[]> {
  return (await lists.recipes()).map((r) => ({
    service: "imagebuilder",
    type: "Image recipe",
    id: r.arn!,
    name: `${r.name} ${lists.versionOf(r.arn)}`,
    href: `/imagebuilder?tab=recipes`,
    tags: r.tags,
  }));
}

export async function components(): Promise<InventoryItem[]> {
  return (await lists.components()).map((c) => ({
    service: "imagebuilder",
    type: "Image Builder component",
    id: c.arn!,
    name: `${c.name} ${c.version}`,
    href: `/imagebuilder/component?arn=${enc(c.arn!)}`,
  }));
}
