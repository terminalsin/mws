import "server-only";

import { ListImagePipelinesCommand } from "@aws-sdk/client-imagebuilder";
import { type InventoryItem } from "@mws-dashboard/aws";

import { imagebuilder } from "./clients";

export async function pipelines(): Promise<InventoryItem[]> {
  const out = await (await imagebuilder()).send(new ListImagePipelinesCommand({}));
  return (out.imagePipelineList ?? []).map((p) => ({ service: "imagebuilder", type: "Image pipeline", id: p.arn!, name: p.name!, href: `/imagebuilder`, tags: p.tags }));
}
