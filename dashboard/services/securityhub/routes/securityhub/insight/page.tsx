import { GetInsightResultsCommand, GetInsightsCommand } from "@aws-sdk/client-securityhub";
import { load } from "@mws-dashboard/aws";
import { ActionForm, AwsIcon, Empty, ErrorNotice, List, Page, Pill, Section, Specs } from "@mws-dashboard/ui";
import { Layers, Trash2 } from "lucide-react";
import type { Metadata } from "next";

import { isManagedInsight, securityhub } from "../../../lib/clients";
import { describeFilters } from "../../../lib/findings";
import { resourceHref } from "../../../lib/links";
import { deleteInsight } from "../actions";
import { EditInsight } from "../forms";

export const metadata: Metadata = { title: "Insight · Security Hub" };

type Props = { searchParams: Promise<{ arn?: string }> };
const ICON = "resource/AmazonCloudWatchMetricsInsights";

/** An insight's point: its findings grouped by one attribute, with counts. */
export default async function Insight({ searchParams }: Props) {
  const { arn = "" } = await searchParams;
  const back = { href: "/securityhub?tab=insights", label: "Insights" };
  const data = await load(async () => {
    const client = await securityhub();
    const [insight, results] = await Promise.all([
      client.send(new GetInsightsCommand({ InsightArns: [arn] })).then((r) => r.Insights?.[0]),
      client.send(new GetInsightResultsCommand({ InsightArn: arn })).then((r) => r.InsightResults),
    ]);
    if (!insight) throw new Error(`Insight ${arn} not found`);
    return { insight, results };
  });
  if (!data.ok) {
    return (
      <Page title="Insight" back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { insight: i, results } = data.value;
  const managed = isManagedInsight(arn);
  const values = results?.ResultValues ?? [];
  const total = values.reduce((n, v) => n + (v.Count ?? 0), 0);
  const max = Math.max(1, ...values.map((v) => v.Count ?? 0));
  const group = i.GroupByAttribute ?? "";
  return (
    <Page
      title={i.Name}
      icon={ICON}
      back={back}
      subtitle={arn}
      actions={
        !managed && (
          <>
            <EditInsight arn={arn} name={i.Name!} group={group} severity={i.Filters?.SeverityLabel?.[0]?.Value} />
            <ActionForm action={deleteInsight.bind(null, arn)} submit="Delete insight" icon={<Trash2 size={16} />} tone="danger" confirm={`Delete insight ${i.Name}?`} testId="delete-insight" />
          </>
        )
      }
    >
      <Specs
        items={[
          { label: "Grouped by", icon: <Layers size={15} />, value: group },
          { label: "Findings", icon: <AwsIcon icon="resource/AWSSecurityHubFinding" size={16} />, value: total },
          managed && { label: "Managed", icon: <AwsIcon icon="service/AWSSecurityHub" size={16} />, value: "Managed by Security Hub" },
        ]}
      />
      <div className="chips">
        {describeFilters(i.Filters as Record<string, unknown>).map((f) => (
          <span key={f} className="tag">
            <span>{f}</span>
          </span>
        ))}
      </div>
      <Section title="Results" count={values.length} plain>
        <List
          label="Results"
          empty={<Empty icon={ICON}>No findings match</Empty>}
          rows={values.map((v) => ({
            key: v.GroupByAttributeValue!,
            title: v.GroupByAttributeValue,
            subtitle: (
              <span className="hbar-track" style={{ display: "block", width: "100%", maxWidth: 320 }}>
                <span className="hbar" style={{ display: "block", width: `${((v.Count ?? 0) / max) * 100}%` }} />
              </span>
            ),
            href: group === "ResourceId" ? resourceHref(v.GroupByAttributeValue) : undefined,
            meta: <Pill>{v.Count}</Pill>,
          }))}
        />
      </Section>
    </Page>
  );
}
