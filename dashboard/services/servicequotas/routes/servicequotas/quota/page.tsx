import {
  GetAWSDefaultServiceQuotaCommand,
  GetServiceQuotaCommand,
  ListRequestedServiceQuotaChangeHistoryByQuotaCommand,
  ListTagsForResourceCommand,
} from "@aws-sdk/client-service-quotas";
import { all, load, region } from "@mws-dashboard/aws";
import { ActionForm, Empty, ErrorNotice, Facts, Field, List, Metric, Metrics, Page, Pill, Section, Sheet, Tags } from "@mws-dashboard/ui";
import { LiveRefresh } from "@mws-dashboard/ui/client";
import { ArrowUp, LifeBuoy, Tag } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { ICONS, quotas } from "../../../lib/clients";
import { IncreaseFields } from "../../../lib/increase-fields";
import { OPEN, tone, usage, utilization } from "../../../lib/quotas";
import { createSupportCase, requestIncrease, saveQuotaTags } from "../actions";
import { iconOf, requestRow } from "../rows";

type Props = { searchParams: Promise<{ service?: string; code?: string }> };

export const metadata: Metadata = { title: "Quota" };

const PERIOD: Record<string, string> = { SECOND: "s", MINUTE: "min", HOUR: "h", DAY: "d", WEEK: "w" };

/** One quota: its applied and default values, usage, history and tags. */
export default async function Quota({ searchParams }: Props) {
  const { service = "", code = "" } = await searchParams;
  const back = { href: `/servicequotas?service=${service}`, label: service };
  const where = await region();
  const data = await load(async () => {
    const c = await quotas();
    const [applied, defaults, history] = await Promise.all([
      c.send(new GetServiceQuotaCommand({ ServiceCode: service, QuotaCode: code })).then((r) => r.Quota),
      c.send(new GetAWSDefaultServiceQuotaCommand({ ServiceCode: service, QuotaCode: code })).then((r) => r.Quota),
      all((NextToken) => c.send(new ListRequestedServiceQuotaChangeHistoryByQuotaCommand({ ServiceCode: service, QuotaCode: code, NextToken })), (r) => r.RequestedQuotas, (r) => r.NextToken),
    ]);
    const q = (applied ?? defaults)!;
    const [used, tags] = await Promise.all([
      usage([q]).then((m) => m.get(code), () => undefined),
      q.QuotaArn ? c.send(new ListTagsForResourceCommand({ ResourceARN: q.QuotaArn })).then((r) => r.Tags ?? [], () => []) : [],
    ]);
    return { q, applied, defaults, history, used, tags };
  });
  if (!data.ok) {
    return (
      <Page title={code} icon={iconOf(service)} back={back}>
        <ErrorNotice error={data.error} />
      </Page>
    );
  }
  const { q, applied, defaults, history, used, tags } = data.value;
  const value = applied?.Value ?? defaults?.Value ?? 0;
  const open = history.find((r) => OPEN.has(r.Status!));
  const pct = utilization(used, value);
  const sorted = [...history].sort((a, b) => +new Date(b.Created!) - +new Date(a.Created!));
  const metric = q.UsageMetric;
  return (
    <Page
      title={q.QuotaName}
      icon={iconOf(service)}
      back={{ href: back.href, label: q.ServiceName ?? service }}
      subtitle={q.QuotaArn}
      actions={
        <>
          {q.QuotaArn && (
            <Sheet title="Tags" label="Edit tags" icon={<Tag size={16} />} testId="edit-tags">
              <ActionForm action={saveQuotaTags.bind(null, q.QuotaArn)} submit="Save" testId="edit-tags">
                <Field label="Tags" format="tags">
                  <textarea name="tags" rows={6} placeholder="owner=platform" defaultValue={tags.map((t) => `${t.Key}=${t.Value}`).join("\n")} />
                </Field>
              </ActionForm>
            </Sheet>
          )}
          {open?.Status === "PENDING" && (
            <ActionForm action={createSupportCase.bind(null, open.Id!)} submit="Open a support case" icon={<LifeBuoy size={16} />} testId="support-case" />
          )}
          {q.Adjustable && !open && (
            <Sheet title={`Request increase: ${q.QuotaName}`} label="Request increase" icon={<ArrowUp size={16} />} testId={`increase-${code}`}>
              <ActionForm action={requestIncrease.bind(null, service, code)} submit="Request" testId={`increase-${code}`}>
                <IncreaseFields value={value} />
              </ActionForm>
            </Sheet>
          )}
        </>
      }
    >
      <LiveRefresh when={open?.Status === "PENDING"} />
      <Metrics>
        <Metric label="Applied value" value={value} tone={applied && defaults && applied.Value !== defaults.Value ? "info" : undefined} />
        {defaults && <Metric label="AWS default" value={defaults.Value} />}
        {used !== undefined && <Metric label="Usage" value={pct !== undefined ? `${used} (${pct}%)` : used} tone={pct !== undefined && pct >= 80 ? (tone(pct) as "warn" | "bad") : undefined} />}
        {open && <Metric label={`Requested (${open.Status!.toLowerCase().replace(/_/g, " ")})`} value={open.DesiredValue} tone="info" />}
      </Metrics>
      <Facts
        items={[
          ["Quota code", <code key="c">{code}</code>],
          q.Description && ["Description", q.Description],
          ["Adjustable", q.Adjustable ? "yes" : "no"],
          ["Scope", q.GlobalQuota ? "global" : where],
          q.Unit && q.Unit !== "None" && ["Unit", q.Unit],
          q.Period?.PeriodValue && ["Per", `${q.Period.PeriodValue} ${PERIOD[q.Period.PeriodUnit ?? ""] ?? q.Period.PeriodUnit?.toLowerCase()}`],
          q.QuotaAppliedAtLevel && q.QuotaAppliedAtLevel !== "ACCOUNT" && ["Applied at", q.QuotaAppliedAtLevel.toLowerCase()],
          q.QuotaContext?.ContextScope && ["Context", `${q.QuotaContext.ContextScope.toLowerCase()} ${q.QuotaContext.ContextId ?? ""}`.trim()],
          q.ErrorReason?.ErrorMessage && ["Error", <Pill key="e" tone="bad">{q.ErrorReason.ErrorMessage}</Pill>],
          metric?.MetricName && [
            "Usage metric",
            <Link
              key="m"
              href={`/metrics?ns=${encodeURIComponent(metric.MetricNamespace ?? "AWS/Usage")}&metric=${encodeURIComponent(metric.MetricName)}&dims=${encodeURIComponent(JSON.stringify(Object.entries(metric.MetricDimensions ?? {}).map(([Name, Value]) => ({ Name, Value }))))}&stat=${metric.MetricStatisticRecommendation ?? "Maximum"}`}
            >
              {metric.MetricNamespace} · {metric.MetricName}
            </Link>,
          ],
          tags.length > 0 && ["Tags", <Tags key="t" tags={tags} />],
        ]}
      />
      <Section title="Request history" count={history.length} plain>
        <List label="Requests" empty={<Empty icon={ICONS.quotas} />} rows={sorted.map((r) => ({ ...requestRow(r, false), href: undefined }))} />
      </Section>
    </Page>
  );
}
