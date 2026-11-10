import { createResource, listResources } from "@mws-dashboard/aws/resources";
import { isResourceKind, type ResourceKind, type ResourceOption } from "@mws-dashboard/ui/resources";
import { cookies } from "next/headers";
import type { NextRequest } from "next/server";

export const dynamic = "force-dynamic";

// Lists for the console's resource pickers, shared by every open picker of
// the same kind for a few seconds (a page often has several).
const cache = new Map<string, { at: number; items: Promise<ResourceOption[]> }>();
const TTL = 4_000;

async function key(kind: string) {
  return `${(await cookies()).get("mws-region")?.value ?? ""}|${kind}`;
}

/** GET /api/resources?kind=iam-role[,sns-topic...] → { items } */
export async function GET(request: NextRequest) {
  const kinds = (request.nextUrl.searchParams.get("kind") ?? "").split(",").filter(isResourceKind);
  if (!kinds.length) return Response.json({ error: "Unknown kind" }, { status: 400 });
  const lists = await Promise.all(
    kinds.map(async (kind) => {
      const k = await key(kind);
      const hit = cache.get(k);
      if (hit && Date.now() - hit.at < TTL) return hit.items;
      const items = listResources(kind);
      cache.set(k, { at: Date.now(), items });
      return items;
    }),
  );
  return Response.json({ items: lists.flat() });
}

/** POST /api/resources { kind, name, service? } → { item } or { error } */
export async function POST(request: NextRequest) {
  const body = (await request.json().catch(() => ({}))) as { kind?: string; name?: string; service?: string };
  if (!body.kind || !isResourceKind(body.kind) || !body.name?.trim()) return Response.json({ error: "A kind and a name are needed" }, { status: 400 });
  try {
    const item = await createResource(body.kind as ResourceKind, body.name.trim(), { service: body.service });
    cache.delete(await key(body.kind));
    return Response.json({ item });
  } catch (e) {
    const message = e instanceof Error ? `${e.name && e.name !== "Error" ? `${e.name}: ` : ""}${e.message}` : String(e);
    return Response.json({ error: message }, { status: 400 });
  }
}
