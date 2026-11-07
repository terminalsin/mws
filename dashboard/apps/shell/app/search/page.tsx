import { search } from "@mws-dashboard/ai";
import { AwsIcon, Empty, List, Page, Status } from "@mws-dashboard/ui";
import type { Metadata } from "next";

import { iconOf, inventory, searchText } from "../../lib/inventory";

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
          icon: <AwsIcon icon={iconOf(h)} size={24} label={h.type} />,
          title: h.name,
          subtitle: h.detail,
          meta: h.signal && <Status tone={h.signal.tone}>{h.signal.text}</Status>,
          href: h.href,
          external: true,
        }))}
      />
    </Page>
  );
}
