import { DescribeOpsItemsCommand, type OpsItemFilter } from "@aws-sdk/client-ssm";
import { ago, all, load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, Field, List, Metric, Metrics, Page, Pill, Segments, Sheet } from "@mws-dashboard/ui";
import { CreateOpsItem } from "@mws-dashboard/ui/model/ssm";
import type { Metadata } from "next";

import { ICONS, ssm } from "../../../lib/clients";
import { SsmNav } from "../../../lib/nav";
import { tone, words } from "../../../lib/status";
import { createOpsItem } from "./actions";
import { OpsItemFields } from "./fields";

export const metadata: Metadata = { title: "OpsCenter" };

type Props = { searchParams: Promise<{ status?: string }> };

const VIEWS = [
  { id: "open", label: "Open and in progress", values: ["Open", "InProgress"] },
  { id: "resolved", label: "Resolved", values: ["Resolved"] },
  { id: "all", label: "All", values: [] as string[] },
];

export default async function OpsItems({ searchParams }: Props) {
  const { status = "open" } = await searchParams;
  const view = VIEWS.find((v) => v.id === status) ?? VIEWS[0];
  const c = await ssm();
  const filters: OpsItemFilter[] = view.values.length ? [{ Key: "Status", Operator: "Equal", Values: view.values }] : [];
  const list = await load(() => all((NextToken) => c.send(new DescribeOpsItemsCommand({ OpsItemFilters: filters.length ? filters : undefined, NextToken, MaxResults: 50 })), (r) => r.OpsItemSummaries, (r) => r.NextToken));
  const create = (
    <Sheet title="Create OpsItem" label="Create OpsItem" testId="create-opsitem">
      <ActionForm action={createOpsItem} submit="Create" testId="create-opsitem">
        <OpsItemFields />
        <Field label="Source" rule={CreateOpsItem.Source}>
          <input name="source" required defaultValue="console" />
        </Field>
        <Field label="Type" rule={CreateOpsItem.OpsItemType} known={["/aws/issue", "/aws/insight"]}>
          <input name="type" placeholder="/aws/issue" />
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="OpsCenter" icon={ICONS.ssm} actions={create}>
      <SsmNav active="opsitems" />
      {list.ok && view.id === "open" && list.value.length > 0 && (
        <Metrics>
          <Metric label="Open" value={list.value.filter((o) => o.Status === "Open").length} tone="warn" />
          <Metric label="In progress" value={list.value.filter((o) => o.Status === "InProgress").length} />
          <Metric label="Priority 1–2" value={list.value.filter((o) => (o.Priority ?? 5) <= 2).length} tone="bad" />
        </Metrics>
      )}
      <Segments label="Status" items={VIEWS.map((v) => ({ label: v.label, href: `/ssm/opsitems?status=${v.id}`, active: v.id === view.id }))} />
      {list.ok ? (
        <List
          label="OpsItems"
          empty={<Empty icon={ICONS.opsItem} />}
          rows={list.value
            .sort((a, b) => (a.Priority ?? 9) - (b.Priority ?? 9) || (b.CreatedTime?.getTime() ?? 0) - (a.CreatedTime?.getTime() ?? 0))
            .map((o) => ({
              key: o.OpsItemId!,
              icon: <AwsIcon icon={ICONS.opsItem} size={24} />,
              title: o.Title,
              subtitle: [o.OpsItemId, o.Source, o.OpsItemType, o.Category].filter(Boolean).join(" · "),
              href: `/ssm/opsitem?id=${o.OpsItemId}`,
              meta: (
                <>
                  {o.Priority && <Pill tone={o.Priority <= 2 ? "bad" : "neutral"}>P{o.Priority}</Pill>}
                  {o.Severity && <Pill>sev {o.Severity}</Pill>}
                  <span>{ago(o.CreatedTime)}</span>
                  <Pill tone={tone(o.Status)}>{words(o.Status)}</Pill>
                </>
              ),
            }))}
        />
      ) : (
        <ErrorNotice error={list.error} />
      )}
    </Page>
  );
}
