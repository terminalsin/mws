import { search } from "@mws-dashboard/ai";
import { AwsIcon, Empty, List, Page } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { inventory, searchText, serviceOf } from "../../lib/inventory";

export const metadata: Metadata = { title: "Search" };

type Props = { searchParams: Promise<{ q?: string }> };

export default async function Search({ searchParams }: Props) {
  const q = (await searchParams).q ?? "";
  const items = await inventory();
  const hits = await search(q, items.map((i) => ({ ...i, text: searchText(i) })), 100);
  return (
    <Page title={q || "Search"}>
      <form action="/search" className="search-page-form">
        <input name="q" defaultValue={q} placeholder="Search resources" aria-label="Search resources" autoFocus />
      </form>
      <List
        label="Results"
        empty={q ? <Empty>No matches</Empty> : null}
        rows={hits.map((h) => ({
          key: h.id,
          icon: <AwsIcon icon={serviceOf(h)?.icon ?? "category/ManagementTools"} size={24} />,
          title: h.name,
          subtitle: `${serviceOf(h)?.short ?? h.service} · ${h.type}`,
          meta: h.detail,
          href: h.href,
          external: true,
        }))}
      />
    </Page>
  );
}
