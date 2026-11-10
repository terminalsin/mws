import { ListCostCategoryDefinitionsCommand } from "@aws-sdk/client-cost-explorer";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Sheet, Status } from "@mws-dashboard/ui";
import { Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { ICONS, ce } from "../../../lib/clients";
import { createCostCategory, deleteCostCategory } from "../actions";
import { CategoryFields } from "./fields";

export const metadata: Metadata = { title: "Cost categories" };

function NewCostCategory({ names }: { names: string[] }) {
  return (
    <Sheet title="New cost category" label="Create cost category" testId="create-cost-category">
      <ActionForm action={createCostCategory} submit="Create" testId="create-cost-category">
        <CategoryFields names={names} />
      </ActionForm>
    </Sheet>
  );
}

export default async function CostCategories() {
  const list = await load(async () => {
    const client = await ce();
    return all((NextToken) => client.send(new ListCostCategoryDefinitionsCommand({ NextToken })), (r) => r.CostCategoryReferences, (r) => r.NextToken);
  });
  if (!list.ok) {
    return (
      <Page title="Cost categories">
        <ErrorNotice error={list.error} />
      </Page>
    );
  }
  const categories = list.value.sort((a, b) => a.Name!.localeCompare(b.Name!));
  const names = categories.map((c) => c.Name!);
  return (
    <Page title="Cost categories" actions={<NewCostCategory names={names} />}>
      <List
        label="Cost categories"
        empty={<Empty icon={ICONS.category} action={<NewCostCategory names={[]} />} />}
        rows={categories.map((c) => ({
          key: c.CostCategoryArn!,
          icon: <AwsIcon icon={ICONS.category} size={24} />,
          title: c.Name!,
          href: `/ce/category?arn=${encodeURIComponent(c.CostCategoryArn!)}`,
          subtitle: c.Values?.length ? c.Values.join(", ") : undefined,
          meta: (
            <>
              {c.ProcessingStatus?.some((s) => s.Status === "PROCESSING") && <Status tone="info">Processing</Status>}
              <Pill title="Rules">{c.NumberOfRules ?? 0}</Pill>
              {c.EffectiveStart && <span>{c.EffectiveStart.slice(0, 10)}</span>}
            </>
          ),
          actions: (
            <ActionForm action={deleteCostCategory.bind(null, c.CostCategoryArn!, "")} submit={`Delete ${c.Name}`} icon={<Trash2 size={15} />} tone="danger" confirm={`Delete ${c.Name}?`} />
          ),
        }))}
      />
    </Page>
  );
}
