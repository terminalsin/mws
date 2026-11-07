import { search } from "@mws-dashboard/ai";
import type { SearchHit } from "@mws-dashboard/ui";
import type { NextRequest } from "next/server";

import { inventory, searchText, serviceOf } from "../../../lib/inventory";

export const dynamic = "force-dynamic";

/** Semantic search across every zone's resources. With no query it returns
 * what needs attention. */
export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get("q") ?? "";
  const items = await inventory();
  const ranked = q.trim()
    ? await search(q, items.map((i) => ({ ...i, text: searchText(i) })), 40)
    : items.filter((i) => i.signal).map((i) => ({ ...i, text: "", score: 1 }));
  const hits: SearchHit[] = ranked.map((i) => {
    const s = serviceOf(i);
    return {
      id: i.id,
      service: i.service,
      serviceName: s?.short ?? i.service,
      icon: s?.icon ?? "category/ManagementTools",
      type: i.type,
      name: i.name,
      detail: i.signal?.text ?? i.detail,
      href: i.href,
      score: i.score,
    };
  });
  return Response.json({ hits });
}
