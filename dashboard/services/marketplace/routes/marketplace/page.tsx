import { ago, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Section, Sheet } from "@mws-dashboard/ui";
import { Eraser, Users } from "lucide-react";
import type { Metadata } from "next";

import { ICONS } from "../../lib/clients";
import { products, PRODUCT_ICONS, records, subscriptions } from "../../lib/marketplace";
import { ProductFields } from "../../lib/product-fields";
import { clearRecords, createProduct } from "./actions";
import { Usage } from "./usage";

export const metadata: Metadata = { title: "Marketplace" };

type Props = { searchParams: Promise<{ tab?: string }> };

async function Records() {
  const [list, catalog] = await Promise.all([load(() => records()), load(products)]);
  if (!list.ok) return <ErrorNotice error={list.error} />;
  const title = (code: string) => (catalog.ok && catalog.value.find((p) => p.productCode === code)?.title) || code;
  const productType = (code: string) => (catalog.ok ? catalog.value.find((p) => p.productCode === code)?.productType : undefined);
  return (
    <>
      {list.value.length > 0 && (
        <Section title="Usage">
          <Usage records={list.value} />
        </Section>
      )}
      <Section title="Records" count={list.value.length} plain actions={list.value.length > 0 ? <ActionForm action={clearRecords} submit="Clear records" icon={<Eraser size={15} />} tone="danger" confirm="Forget every metering record?" /> : undefined}>
        <List
          label="Metering records"
          empty={<Empty icon={ICONS.marketplace} />}
          rows={[...list.value].reverse().map((r) => ({
            key: r.meteringRecordId,
            icon: <AwsIcon icon={PRODUCT_ICONS[productType(r.productCode) ?? ""] ?? ICONS.marketplace} size={22} />,
            title: `${r.quantity.toLocaleString()} × ${r.dimension}`,
            subtitle: `${title(r.productCode)} · ${r.customerIdentifier ?? r.customerAWSAccountId}`,
            meta: (
              <>
                <Pill>{r.operation}</Pill>
                <span>{ago(r.timestamp)}</span>
              </>
            ),
          }))}
        />
      </Section>
    </>
  );
}

export default async function Marketplace({ searchParams }: Props) {
  const { tab = "products" } = await searchParams;
  if (tab === "records") {
    return (
      <Page title="Metering records">
        <Records />
      </Page>
    );
  }
  const [catalog, subs] = await Promise.all([load(products), load(() => subscriptions())]);
  const create = (
    <Sheet title="Create product" label="Create product" testId="create-product">
      <ActionForm action={createProduct} submit="Create product" testId="create-product">
        <ProductFields titles={catalog.ok ? catalog.value.map((p) => p.title) : []} codes={catalog.ok ? catalog.value.map((p) => p.productCode) : []} />
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Products" actions={create}>
      {catalog.ok ? (
        <List
          label="Products"
          empty={<Empty icon={ICONS.marketplace} action={create} />}
          rows={catalog.value.map((p) => {
            const buyers = subs.ok ? subs.value.filter((s) => s.productCode === p.productCode && s.status === "Active").length : 0;
            return {
              key: p.productCode,
              icon: <AwsIcon icon={PRODUCT_ICONS[p.productType] ?? ICONS.marketplace} size={22} />,
              title: p.title || p.productCode,
              subtitle: <code>{p.productCode}</code>,
              href: `/marketplace/product?code=${p.productCode}`,
              meta: (
                <>
                  {buyers > 0 && <Pill icon={<Users size={11} />}>{buyers}</Pill>}
                  {p.createdAt && <span>{ago(p.createdAt)}</span>}
                </>
              ),
            };
          })}
        />
      ) : (
        <ErrorNotice error={catalog.error} />
      )}
    </Page>
  );
}
