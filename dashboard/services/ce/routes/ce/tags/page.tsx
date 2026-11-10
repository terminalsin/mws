import { ListCostAllocationTagBackfillHistoryCommand, ListCostAllocationTagsCommand } from "@aws-sdk/client-cost-explorer";
import { all, load } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Field, List, Page, Section, Segments, Sheet, Status } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { History, Power, PowerOff, Tag } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, ce } from "../../../lib/clients";
import { day, monthStart, mwsNow } from "../../../lib/clock";
import { href } from "../../../lib/query";
import { backfillTags, setTagStatus } from "../actions";

export const metadata: Metadata = { title: "Cost allocation tags" };

type Props = { searchParams: Promise<{ type?: string }> };

export default async function CostAllocationTags({ searchParams }: Props) {
  const { type = "UserDefined" } = await searchParams;
  const now = await mwsNow();
  const data = await load(async () => {
    const client = await ce();
    const [tags, backfills] = await Promise.all([
      all((NextToken) => client.send(new ListCostAllocationTagsCommand({ NextToken })), (r) => r.CostAllocationTags, (r) => r.NextToken),
      all((NextToken) => client.send(new ListCostAllocationTagBackfillHistoryCommand({ NextToken })), (r) => r.BackfillRequests, (r) => r.NextToken).catch(() => []),
    ]);
    return { tags, backfills };
  });
  if (!data.ok) {
    return (
      <Page title="Cost allocation tags">
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { tags, backfills } = data.value;
  const shown = tags.filter((t) => t.Type === type).sort((a, b) => a.TagKey!.localeCompare(b.TagKey!));
  const inactive = shown.filter((t) => t.Status !== "Active").map((t) => t.TagKey!);
  const months = Array.from({ length: 13 }, (_, i) => day(monthStart(now, -i)));
  const running = backfills.some((b) => b.BackfillStatus === "PROCESSING");
  const backfill = (
    <Sheet title="Backfill tags" label="Backfill tags" icon={<History size={15} />} testId="backfill-tags">
      <ActionForm action={backfillTags} submit="Start backfill" testId="backfill-tags">
        <Field label="Apply active tags from">
          <select name="from" defaultValue={months[1]}>
            {months.map((m) => (
              <option key={m} value={m}>
                {m.slice(0, 7)}
              </option>
            ))}
          </select>
        </Field>
      </ActionForm>
    </Sheet>
  );
  return (
    <Page title="Cost allocation tags" back={{ href: "/ce", label: "Cost and usage" }} actions={!running ? backfill : undefined}>
      <LiveRefresh when={running} />
      <Segments
        items={[
          { label: "User-defined", href: "/ce/tags", active: type !== "AWSGenerated", count: tags.filter((t) => t.Type === "UserDefined").length },
          { label: "AWS-generated", href: "/ce/tags?type=AWSGenerated", active: type === "AWSGenerated", count: tags.filter((t) => t.Type === "AWSGenerated").length },
        ]}
      />
      <Section
        plain
        actions={
          inactive.length > 1 ? (
            <ActionForm action={setTagStatus.bind(null, inactive, "Active")} submit={`Activate all ${inactive.length}`} icon={<Power size={15} />} />
          ) : undefined
        }
      >
        <List
          label="Cost allocation tags"
          empty={<Empty icon={ICONS.ce}>Tags show up here once tagged resources incur costs.</Empty>}
          rows={shown.map((t) => {
            const active = t.Status === "Active";
            return {
              key: t.TagKey!,
              icon: <Tag size={18} />,
              title: active ? <Link href={href({ groups: [`TAG:${t.TagKey}`] })}>{t.TagKey}</Link> : t.TagKey,
              subtitle: t.LastUsedDate ? `Last used ${t.LastUsedDate.slice(0, 10)}` : undefined,
              meta: (
                <>
                  <Status tone={active ? "good" : "neutral"}>{t.Status ?? ""}</Status>
                  {t.LastUpdatedDate && <span title="Status changed">{t.LastUpdatedDate.slice(0, 10)}</span>}
                </>
              ),
              actions: (
                <ActionForm
                  action={setTagStatus.bind(null, [t.TagKey!], active ? "Inactive" : "Active")}
                  submit={`${active ? "Deactivate" : "Activate"} ${t.TagKey}`}
                  icon={active ? <PowerOff size={15} /> : <Power size={15} />}
                  tone={active ? "danger" : "plain"}
                />
              ),
            };
          })}
        />
      </Section>
      {backfills.length > 0 && (
        <Section title="Backfill history" count={backfills.length} plain>
          <List
            label="Backfill history"
            rows={backfills.map((b) => ({
              key: `${b.RequestedAt}`,
              icon: <History size={18} />,
              title: `From ${b.BackfillFrom?.slice(0, 7)}`,
              subtitle: `Requested ${b.RequestedAt?.slice(0, 16).replace("T", " ")}${b.CompletedAt ? ` · completed ${b.CompletedAt.slice(0, 16).replace("T", " ")}` : ""}`,
              meta: <Status tone={b.BackfillStatus === "SUCCEEDED" ? "good" : b.BackfillStatus === "FAILED" ? "bad" : "warn"}>{b.BackfillStatus?.toLowerCase() ?? ""}</Status>,
            }))}
          />
        </Section>
      )}
    </Page>
  );
}
