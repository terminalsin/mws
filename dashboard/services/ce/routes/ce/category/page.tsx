import { DescribeCostCategoryDefinitionCommand, GetCostCategoriesCommand } from "@aws-sdk/client-cost-explorer";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, CodeBlock, ErrorNotice, Facts, Field, List, Page, Pill, Section, Sheet, Specs, Status } from "@mws-dashboard/ui";
import { BarChart3, CalendarClock, ListTree, Pencil, Split, Trash2 } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ce } from "../../../lib/clients";
import { addDays, day, monthStart, mwsNow } from "../../../lib/clock";
import { href } from "../../../lib/query";
import { deleteCostCategory, updateCostCategory } from "../actions";

export const metadata: Metadata = { title: "Cost category" };

type Props = { searchParams: Promise<{ arn?: string }> };

export default async function CostCategory({ searchParams }: Props) {
  const arn = (await searchParams).arn ?? "";
  const back = { href: "/ce/categories", label: "Cost categories" };
  const now = await mwsNow();
  const data = await load(async () => {
    const client = await ce();
    const c = (await client.send(new DescribeCostCategoryDefinitionCommand({ CostCategoryArn: arn }))).CostCategory!;
    const values = await client
      .send(new GetCostCategoriesCommand({ TimePeriod: { Start: day(monthStart(now, -2)), End: day(addDays(now, 1)) }, CostCategoryName: c.Name }))
      .then((r) => r.CostCategoryValues ?? [], () => [] as string[]);
    return { c, values };
  });
  if (!data.ok) {
    return (
      <Page title="Cost category" icon={ICONS.category} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { c, values } = data.value;
  const ruleValues = [...new Set((c.Rules ?? []).map((r) => r.Value ?? (r.InheritedValue ? `(${r.InheritedValue.DimensionName} ${r.InheritedValue.DimensionKey ?? ""})` : "")))];
  const processing = c.ProcessingStatus?.some((s) => s.Status === "PROCESSING");
  return (
    <Page
      title={c.Name}
      icon={ICONS.category}
      back={back}
      subtitle={c.CostCategoryArn}
      actions={
        <>
          <Link className="icon-button plain" href={href({ groups: [`COST_CATEGORY:${c.Name}`] })} aria-label="Costs by this category" title="Costs by this category">
            <BarChart3 size={16} />
          </Link>
          <Sheet title="Edit cost category" label="Edit cost category" icon={<Pencil size={15} />} testId="edit-cost-category">
            <ActionForm action={updateCostCategory.bind(null, c.CostCategoryArn!)} submit="Save" testId="edit-cost-category">
              <Field label="Rules" format="json">
                <textarea name="rules" rows={12} spellCheck={false} className="code-editor" defaultValue={JSON.stringify(c.Rules ?? [], null, 2)} required />
              </Field>
              <Field label="Split charge rules" format="json" hint="Optional: share a value's costs out to others">
                <textarea name="split" rows={4} spellCheck={false} className="code-editor" defaultValue={c.SplitChargeRules?.length ? JSON.stringify(c.SplitChargeRules, null, 2) : ""} />
              </Field>
              <div className="form-row">
                <Field label="Uncategorized costs">
                  <input name="default" defaultValue={c.DefaultValue} placeholder="Other" />
                </Field>
                <Field label="Effective from">
                  <input name="start" type="month" defaultValue={c.EffectiveStart?.slice(0, 7)} />
                </Field>
              </div>
            </ActionForm>
          </Sheet>
          <ActionForm action={deleteCostCategory.bind(null, c.CostCategoryArn!, "/ce/categories")} submit="Delete cost category" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete ${c.Name}?`} />
        </>
      }
    >
      <Specs
        items={[
          processing && { label: "Status", icon: <ListTree size={15} />, value: <Status tone="info">Processing</Status> },
          { label: "Rules", icon: <ListTree size={15} />, value: c.Rules?.length ?? 0 },
          (c.SplitChargeRules?.length ?? 0) > 0 && { label: "Split charge rules", icon: <Split size={15} />, value: c.SplitChargeRules!.length },
          c.EffectiveStart && { label: "Effective", icon: <CalendarClock size={15} />, value: `${c.EffectiveStart.slice(0, 10)}${c.EffectiveEnd ? ` → ${c.EffectiveEnd.slice(0, 10)}` : ""}` },
        ]}
      />
      <Section title="Values" count={ruleValues.length + (c.DefaultValue ? 1 : 0)} plain>
        <List
          label="Values"
          rows={[...ruleValues, ...(c.DefaultValue ? [c.DefaultValue] : [])].map((v) => ({
            key: v,
            icon: <AwsIcon icon={ICONS.category} size={20} />,
            title: v,
            href: v.startsWith("(") ? undefined : href({ groups: ["DIMENSION:SERVICE"], filter: `COST_CATEGORY:${c.Name}`, values: [v] }),
            meta: (
              <>
                {v === c.DefaultValue && <Pill>default</Pill>}
                {(values as string[]).includes(v) && <Pill tone="good">has costs</Pill>}
              </>
            ),
          }))}
        />
      </Section>
      <Section title="Rules">
        <CodeBlock value={JSON.stringify(c.Rules ?? [])} label="Rules" />
      </Section>
      {(c.SplitChargeRules?.length ?? 0) > 0 && (
        <Section title="Split charge rules">
          <Facts items={c.SplitChargeRules!.map((r) => [r.Source, `${r.Method?.toLowerCase()} → ${(r.Targets ?? []).join(", ")}`])} />
        </Section>
      )}
    </Page>
  );
}
